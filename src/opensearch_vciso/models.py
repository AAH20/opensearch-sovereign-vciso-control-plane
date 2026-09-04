"""Core data models for OpenSearch vCISO, CRQ, GRC, and SOC Yield."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class AssetCriticality(str, Enum):
    TIER_0 = "TIER_0"  # Core billing, customer PII database, root IAM
    TIER_1 = "TIER_1"  # Production API gateways, customer-facing workloads
    TIER_2 = "TIER_2"  # Internal enterprise tools, logging infra, staging
    TIER_3 = "TIER_3"  # Isolated dev/test environments


@dataclass
class SecurityAsset:
    asset_id: str
    name: str
    criticality: AssetCriticality
    asset_value_usd: float
    data_classification: str  # RESTRICTED, CONFIDENTIAL, INTERNAL, PUBLIC
    is_fips_compliant: bool = True
    owner: str = "security-operations"


@dataclass
class SecurityFinding:
    finding_id: str
    detector_id: str
    rule_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    mitre_technique: str
    target_asset_id: str
    timestamp: str
    raw_telemetry: dict[str, Any] = field(default_factory=dict)


@dataclass
class CRQResult:
    finding_id: str
    asset_id: str
    asset_criticality: str
    asset_value_usd: float
    single_loss_expectancy_usd: float
    annual_rate_of_occurrence: float
    annualized_loss_expectancy_usd: float
    value_at_risk_95_usd: float
    recommended_mitigation_cost_usd: float
    mitigation_roi_ratio: float
    board_summary: str


@dataclass
class QuestionnaireItem:
    item_id: str
    question: str
    category: str  # access_control, encryption, incident_response, business_continuity
    framework_mapping: list[str]  # SOC2, ISO27001, FedRAMP, DORA


@dataclass
class QuestionnaireAnswer:
    item_id: str
    question: str
    status: str  # VERIFIED, PARTIALLY_SATISFIED, FAILED
    answer_text: str
    evidence_telemetry_ref: str
    framework_mapping: list[str]
