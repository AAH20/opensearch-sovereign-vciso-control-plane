"""Tiered SOC Analyst KPI & Operational Yield Engine (L1, L2, L3).

Quantifies triage velocity, Signal-to-Noise Ratio (SNR), MTTR, reversible lease
containment, and true operational cost per true-positive investigation.
"""

from dataclasses import dataclass
from typing import Any


@dataclass
class AnalystTierMetrics:
    # L1 Triage Metrics
    l1_total_alerts_triaged: int
    l1_true_positives_detected: int
    l1_false_positives_pruned: int
    l1_signal_to_noise_ratio: float
    l1_avg_triage_duration_minutes: float
    l1_escalation_precision_ratio: float
    l1_invariant_auto_gated_alerts: int

    # L2 Investigation & Containment Metrics
    l2_incidents_investigated: int
    l2_mean_time_to_respond_minutes: float
    l2_reversible_lease_containment_rate: float
    l2_root_cause_accuracy_ratio: float
    l2_operational_outages_prevented: int

    # L3 Detection Engineering Metrics
    l3_blindspots_discovered: int
    l3_detection_rules_authored: int
    l3_rule_true_positive_yield_ratio: float
    l3_adversary_emulation_passes: int

    # Unit Economics
    loaded_analyst_hourly_cost_usd: float
    total_investigation_hours: float
    total_operational_cost_usd: float
    cost_per_true_positive_usd: float
    economic_yield_status: str


class SOCYieldEngine:
    """Calculates operational throughput, precision, and unit economics across SOC tiers."""

    def __init__(self, loaded_analyst_hourly_cost_usd: float = 85.0) -> None:
        self.hourly_rate = loaded_analyst_hourly_cost_usd

    def calculate_yield(self, telemetry: dict[str, Any]) -> AnalystTierMetrics:
        # L1 parsing
        l1_data = telemetry.get("tier_1_triage", {})
        l1_total = max(1, l1_data.get("total_alerts", 1200))
        l1_tp = l1_data.get("true_positives", 180)
        l1_fp = l1_data.get("false_positives", l1_total - l1_tp)
        l1_snr = l1_tp / l1_total
        l1_duration = l1_data.get("avg_triage_duration_minutes", 3.2)
        l1_escalated = max(1, l1_data.get("escalated_alerts", 200))
        l1_valid_esc = l1_data.get("valid_escalations", 184)
        l1_precision = l1_valid_esc / l1_escalated
        l1_gated = l1_data.get("invariant_auto_gated_alerts", 420)

        # L2 parsing
        l2_data = telemetry.get("tier_2_incident_response", {})
        l2_incidents = max(1, l2_data.get("incidents_investigated", 45))
        l2_mttr = l2_data.get("mttr_minutes", 22.5)
        l2_leases = l2_data.get("reversible_lease_actions", 42)
        l2_lease_rate = l2_leases / l2_incidents
        l2_rc_accuracy = l2_data.get("root_cause_accuracy", 0.97)
        l2_outages_prevented = l2_data.get("outages_prevented", 8)

        # L3 parsing
        l3_data = telemetry.get("tier_3_engineering", {})
        l3_blindspots = l3_data.get("blindspots_discovered", 14)
        l3_rules = max(1, l3_data.get("detection_rules_authored", 8))
        l3_yield = l3_data.get("rule_true_positive_yield", 0.88)
        l3_passes = l3_data.get("adversary_emulation_passes", 26)

        # Economic calculation
        # Total active hours = L1 triage hours + L2 investigation hours + L3 threat hunting
        l1_hours = (l1_total * l1_duration) / 60.0
        l2_hours = (l2_incidents * l2_mttr) / 60.0
        l3_hours = l3_data.get("engineering_hours", 40.0)
        total_hours = l1_hours + l2_hours + l3_hours
        total_cost = total_hours * self.hourly_rate
        cost_per_tp = total_cost / max(1, l1_tp)

        status = "HIGH_YIELD" if cost_per_tp < 150.0 and l1_snr > 0.12 else "SUBOPTIMAL"

        return AnalystTierMetrics(
            l1_total_alerts_triaged=l1_total,
            l1_true_positives_detected=l1_tp,
            l1_false_positives_pruned=l1_fp,
            l1_signal_to_noise_ratio=l1_snr,
            l1_avg_triage_duration_minutes=l1_duration,
            l1_escalation_precision_ratio=l1_precision,
            l1_invariant_auto_gated_alerts=l1_gated,
            l2_incidents_investigated=l2_incidents,
            l2_mean_time_to_respond_minutes=l2_mttr,
            l2_reversible_lease_containment_rate=l2_lease_rate,
            l2_root_cause_accuracy_ratio=l2_rc_accuracy,
            l2_operational_outages_prevented=l2_outages_prevented,
            l3_blindspots_discovered=l3_blindspots,
            l3_detection_rules_authored=l3_rules,
            l3_rule_true_positive_yield_ratio=l3_yield,
            l3_adversary_emulation_passes=l3_passes,
            loaded_analyst_hourly_cost_usd=self.hourly_rate,
            total_investigation_hours=total_hours,
            total_operational_cost_usd=total_cost,
            cost_per_true_positive_usd=cost_per_tp,
            economic_yield_status=status,
        )
