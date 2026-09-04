"""OpenSearch Sovereign vCISO & Cyber Risk Quantification Control Plane."""

from .models import CRQResult, SecurityFinding, SecurityAsset, QuestionnaireAnswer, QuestionnaireItem
from .crq import CyberRiskQuantifier
from .grc_revenue import GRCRevenueEngine, TrustVault
from .soc_yield import SOCYieldEngine, AnalystTierMetrics
from .threat_emulation import ThreatEmulationEngine, EmulationReport
from .board_memo import BoardMemoGenerator

# Aliases for convenience
FAIRRiskAssessment = CRQResult
QuestionnaireResponse = QuestionnaireAnswer

__all__ = [
    "CyberRiskQuantifier",
    "CRQResult",
    "FAIRRiskAssessment",
    "GRCRevenueEngine",
    "TrustVault",
    "QuestionnaireResponse",
    "QuestionnaireItem",
    "SOCYieldEngine",
    "AnalystTierMetrics",
    "ThreatEmulationEngine",
    "EmulationReport",
    "BoardMemoGenerator",
]
