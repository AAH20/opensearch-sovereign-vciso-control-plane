"""Unit tests for FAIR Cyber Risk Quantification engine."""

import unittest
from opensearch_vciso.models import SecurityFinding, AssetCriticality
from opensearch_vciso.crq import CyberRiskQuantifier


class TestCyberRiskQuantifier(unittest.TestCase):
    def setUp(self) -> None:
        self.quantifier = CyberRiskQuantifier()

    def test_tier_0_critical_finding_quantification(self) -> None:
        finding = SecurityFinding(
            finding_id="F-01",
            detector_id="detector-lsass",
            rule_name="LSASS Dump",
            severity="CRITICAL",
            mitre_technique="T1003.001",
            target_asset_id="asset-stripe-billing-db",
            timestamp="2026-09-04T05:00:00Z",
        )
        result = self.quantifier.quantify_finding(finding, estimated_mitigation_cost_usd=500.0)

        self.assertEqual(result.asset_criticality, "TIER_0")
        self.assertEqual(result.asset_value_usd, 12_500_000.0)
        # Exposure factor for (TIER_0, CRITICAL) is 0.35 -> SLE = 4,375,000.0
        self.assertEqual(result.single_loss_expectancy_usd, 4_375_000.0)
        # ARO is 0.05 -> ALE = 218,750.0
        self.assertEqual(result.annualized_loss_expectancy_usd, 218_750.0)
        # ROI = 218,750 / 500 = 437.5
        self.assertAlmostEqual(result.mitigation_roi_ratio, 437.5)
        self.assertGreater(result.value_at_risk_95_usd, 0.0)
        self.assertIn("presents $4,375,000.00 Single Loss Exposure", result.board_summary)

    def test_unmapped_asset_fallback(self) -> None:
        finding = SecurityFinding(
            finding_id="F-02",
            detector_id="detector-generic",
            rule_name="Unusual Port Scan",
            severity="MEDIUM",
            mitre_technique="T1046",
            target_asset_id="unknown-asset-99",
            timestamp="2026-09-04T05:00:00Z",
        )
        result = self.quantifier.quantify_finding(finding)
        self.assertEqual(result.asset_criticality, "TIER_2")
        self.assertGreater(result.annualized_loss_expectancy_usd, 0.0)


if __name__ == "__main__":
    unittest.main()
