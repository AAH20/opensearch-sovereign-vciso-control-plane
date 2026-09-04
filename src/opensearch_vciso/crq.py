"""Cyber Risk Quantification (CRQ) Engine implementing the FAIR model for OpenSearch."""

import math
from typing import Optional
from .models import SecurityAsset, SecurityFinding, CRQResult, AssetCriticality


class CyberRiskQuantifier:
    """FAIR (Factor Analysis of Information Risk) Quantification Engine.

    Translates OpenSearch Security Analytics alerts and Sigma detections into
    dollar-denominated financial risk exposures (SLE, ARO, ALE, VaR95, ROI).
    """

    def __init__(self, asset_inventory: Optional[dict[str, SecurityAsset]] = None) -> None:
        self.asset_inventory = asset_inventory or self._default_inventory()

    def _default_inventory(self) -> dict[str, SecurityAsset]:
        return {
            "asset-stripe-billing-db": SecurityAsset(
                asset_id="asset-stripe-billing-db",
                name="Primary Financial & Stripe Billing Cluster",
                criticality=AssetCriticality.TIER_0,
                asset_value_usd=12_500_000.0,
                data_classification="RESTRICTED",
                is_fips_compliant=True,
            ),
            "asset-customer-api-gw": SecurityAsset(
                asset_id="asset-customer-api-gw",
                name="Production Customer API Gateway",
                criticality=AssetCriticality.TIER_1,
                asset_value_usd=3_200_000.0,
                data_classification="CONFIDENTIAL",
                is_fips_compliant=True,
            ),
            "asset-internal-logging-opensearch": SecurityAsset(
                asset_id="asset-internal-logging-opensearch",
                name="Enterprise OpenSearch Telemetry Cluster",
                criticality=AssetCriticality.TIER_2,
                asset_value_usd=850_000.0,
                data_classification="INTERNAL",
                is_fips_compliant=False,
            ),
        }

    def quantify_finding(self, finding: SecurityFinding, estimated_mitigation_cost_usd: float = 450.0) -> CRQResult:
        asset = self.asset_inventory.get(finding.target_asset_id)
        if not asset:
            # Default fallback for unmapped assets
            asset = SecurityAsset(
                asset_id=finding.target_asset_id,
                name=f"Generic Asset ({finding.target_asset_id})",
                criticality=AssetCriticality.TIER_2,
                asset_value_usd=500_000.0,
                data_classification="INTERNAL",
            )

        # 1. Exposure Factor (EF) based on asset criticality and finding severity
        ef_matrix = {
            (AssetCriticality.TIER_0, "CRITICAL"): 0.35,
            (AssetCriticality.TIER_0, "HIGH"): 0.20,
            (AssetCriticality.TIER_0, "MEDIUM"): 0.08,
            (AssetCriticality.TIER_1, "CRITICAL"): 0.25,
            (AssetCriticality.TIER_1, "HIGH"): 0.12,
            (AssetCriticality.TIER_1, "MEDIUM"): 0.05,
            (AssetCriticality.TIER_2, "CRITICAL"): 0.15,
            (AssetCriticality.TIER_2, "HIGH"): 0.06,
            (AssetCriticality.TIER_2, "MEDIUM"): 0.02,
            (AssetCriticality.TIER_3, "CRITICAL"): 0.05,
            (AssetCriticality.TIER_3, "HIGH"): 0.02,
            (AssetCriticality.TIER_3, "MEDIUM"): 0.005,
        }
        exposure_factor = ef_matrix.get((asset.criticality, finding.severity.upper()), 0.05)

        # 2. Single Loss Expectancy (SLE) = Asset Value * Exposure Factor
        sle = asset.asset_value_usd * exposure_factor

        # 3. Annual Rate of Occurrence (ARO) based on severity and technique prevalence
        aro_matrix = {
            "CRITICAL": 0.05,  # 1 every 20 years without controls
            "HIGH": 0.25,      # 1 every 4 years
            "MEDIUM": 1.20,    # ~1.2 times per year
            "LOW": 4.00,       # ~4 times per year
        }
        aro = aro_matrix.get(finding.severity.upper(), 0.50)

        # 4. Annualized Loss Expectancy (ALE) = ARO * SLE
        ale = aro * sle

        # 5. Value at Risk (VaR 95%)
        # In FAIR, VaR at 95% confidence bounds the tail exposure
        var_95 = min(asset.asset_value_usd, sle * 1.645 * math.sqrt(max(0.1, aro)))

        # 6. Mitigation ROI Ratio = ALE / Mitigation Cost
        mitigation_cost = max(1.0, estimated_mitigation_cost_usd)
        roi_ratio = ale / mitigation_cost

        summary = (
            f"Finding '{finding.rule_name}' ({finding.severity}) on {asset.criticality.value} asset '{asset.name}' "
            f"presents ${sle:,.2f} Single Loss Exposure and ${ale:,.2f}/yr Annualized Loss Expectancy. "
            f"Mitigation at ${mitigation_cost:,.2f} yields {roi_ratio:.1f}x economic return."
        )

        return CRQResult(
            finding_id=finding.finding_id,
            asset_id=asset.asset_id,
            asset_criticality=asset.criticality.value,
            asset_value_usd=asset.asset_value_usd,
            single_loss_expectancy_usd=sle,
            annual_rate_of_occurrence=aro,
            annualized_loss_expectancy_usd=ale,
            value_at_risk_95_usd=var_95,
            recommended_mitigation_cost_usd=mitigation_cost,
            mitigation_roi_ratio=roi_ratio,
            board_summary=summary,
        )
