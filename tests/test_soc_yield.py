"""Unit tests for SOC Analyst Tier Yield Engine."""

import unittest
from opensearch_vciso.soc_yield import SOCYieldEngine


class TestSOCYield(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = SOCYieldEngine(loaded_analyst_hourly_cost_usd=85.0)

    def test_soc_yield_metrics_and_unit_economics(self) -> None:
        telemetry = {
            "tier_1_triage": {
                "total_alerts": 1000,
                "true_positives": 150,
                "false_positives": 850,
                "avg_triage_duration_minutes": 3.0,
                "escalated_alerts": 160,
                "valid_escalations": 150,
                "invariant_auto_gated_alerts": 400,
            },
            "tier_2_incident_response": {
                "incidents_investigated": 30,
                "mttr_minutes": 20.0,
                "reversible_lease_actions": 28,
                "root_cause_accuracy": 0.98,
                "outages_prevented": 5,
            },
            "tier_3_engineering": {
                "blindspots_discovered": 10,
                "detection_rules_authored": 6,
                "rule_true_positive_yield": 0.85,
                "adversary_emulation_passes": 20,
                "engineering_hours": 30.0,
            },
        }
        metrics = self.engine.calculate_yield(telemetry)

        # L1 triage checks
        self.assertEqual(metrics.l1_total_alerts_triaged, 1000)
        self.assertEqual(metrics.l1_true_positives_detected, 150)
        self.assertAlmostEqual(metrics.l1_signal_to_noise_ratio, 0.15)
        self.assertAlmostEqual(metrics.l1_escalation_precision_ratio, 150 / 160)

        # L2 investigation checks
        self.assertEqual(metrics.l2_incidents_investigated, 30)
        self.assertAlmostEqual(metrics.l2_mean_time_to_respond_minutes, 20.0)
        self.assertAlmostEqual(metrics.l2_reversible_lease_containment_rate, 28 / 30)

        # Unit economics:
        # L1 hours: (1000 * 3) / 60 = 50 hours
        # L2 hours: (30 * 20) / 60 = 10 hours
        # L3 hours: 30 hours
        # Total hours = 90 hours * $85 = $7,650
        # Cost per TP = 7650 / 150 = $51.00
        self.assertEqual(metrics.total_investigation_hours, 90.0)
        self.assertEqual(metrics.total_operational_cost_usd, 7650.0)
        self.assertEqual(metrics.cost_per_true_positive_usd, 51.0)
        self.assertEqual(metrics.economic_yield_status, "HIGH_YIELD")


if __name__ == "__main__":
    unittest.main()
