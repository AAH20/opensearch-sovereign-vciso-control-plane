"""Continuous Adversary Threat Emulation & Detection Validation Engine."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class EmulationTechnique:
    technique_id: str
    name: str
    tactic: str
    synthetic_payload: dict[str, Any]
    expected_detector_id: str


@dataclass
class EmulationResult:
    technique_id: str
    name: str
    detected: bool
    matched_detector: str
    detection_latency_ms: float
    blindspot_detected: bool


@dataclass
class EmulationReport:
    scenario_id: str
    adversary_profile: str
    total_techniques_tested: int
    detected_techniques_count: int
    detection_efficacy_percentage: float
    avg_detection_latency_ms: float
    blindspot_drift_detected: bool
    results: list[EmulationResult]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ThreatEmulationEngine:
    """Continuous Threat Emulation (Breach & Attack Simulation) for OpenSearch."""

    def __init__(self, registered_detectors: list[str]) -> None:
        self.registered_detectors = set(registered_detectors)

    def run_scenario(self, scenario_data: dict[str, Any]) -> EmulationReport:
        scenario_id = scenario_data.get("scenario_id", "SCENARIO-APT29-EMULATION")
        adversary = scenario_data.get("adversary_profile", "APT29 (Cozy Bear)")
        techniques = scenario_data.get("techniques", [])

        results: list[EmulationResult] = []
        total_latency = 0.0

        for t in techniques:
            tech_id = t["technique_id"]
            name = t["name"]
            expected_detector = t["expected_detector_id"]
            latency = t.get("simulated_latency_ms", 120.0)

            # Check if detector is active in OpenSearch
            detected = expected_detector in self.registered_detectors
            blindspot = not detected

            results.append(EmulationResult(
                technique_id=tech_id,
                name=name,
                detected=detected,
                matched_detector=expected_detector if detected else "NONE",
                detection_latency_ms=latency if detected else 0.0,
                blindspot_detected=blindspot,
            ))
            if detected:
                total_latency += latency

        detected_count = sum(1 for r in results if r.detected)
        efficacy = (detected_count / max(1, len(results))) * 100.0
        avg_latency = total_latency / max(1, detected_count)
        has_drift = any(r.blindspot_detected for r in results)

        return EmulationReport(
            scenario_id=scenario_id,
            adversary_profile=adversary,
            total_techniques_tested=len(results),
            detected_techniques_count=detected_count,
            detection_efficacy_percentage=efficacy,
            avg_detection_latency_ms=avg_latency,
            blindspot_drift_detected=has_drift,
            results=results,
        )
