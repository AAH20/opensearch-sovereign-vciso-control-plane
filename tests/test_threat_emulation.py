"""Unit tests for Continuous Threat Emulation Engine."""

import unittest
from opensearch_vciso.threat_emulation import ThreatEmulationEngine


class TestThreatEmulation(unittest.TestCase):
    def test_run_scenario_all_detected(self) -> None:
        registered = ["detector-t1003", "detector-t1486"]
        engine = ThreatEmulationEngine(registered_detectors=registered)

        scenario = {
            "scenario_id": "TEST-SCENARIO",
            "adversary_profile": "Ransomware Cartel",
            "techniques": [
                {
                    "technique_id": "T1003",
                    "name": "OS Credential Dumping",
                    "expected_detector_id": "detector-t1003",
                    "simulated_latency_ms": 75.0,
                },
                {
                    "technique_id": "T1486",
                    "name": "Data Encrypted for Impact",
                    "expected_detector_id": "detector-t1486",
                    "simulated_latency_ms": 125.0,
                },
            ],
        }
        report = engine.run_scenario(scenario)
        self.assertEqual(report.total_techniques_tested, 2)
        self.assertEqual(report.detected_techniques_count, 2)
        self.assertEqual(report.detection_efficacy_percentage, 100.0)
        self.assertEqual(report.avg_detection_latency_ms, 100.0)
        self.assertFalse(report.blindspot_drift_detected)

    def test_run_scenario_with_blindspot_drift(self) -> None:
        registered = ["detector-t1003"]
        engine = ThreatEmulationEngine(registered_detectors=registered)

        scenario = {
            "scenario_id": "TEST-DRIFT",
            "adversary_profile": "APT29",
            "techniques": [
                {
                    "technique_id": "T1003",
                    "name": "OS Credential Dumping",
                    "expected_detector_id": "detector-t1003",
                },
                {
                    "technique_id": "T1078",
                    "name": "Valid Accounts",
                    "expected_detector_id": "missing-detector-t1078",
                },
            ],
        }
        report = engine.run_scenario(scenario)
        self.assertEqual(report.detected_techniques_count, 1)
        self.assertEqual(report.detection_efficacy_percentage, 50.0)
        self.assertTrue(report.blindspot_drift_detected)


if __name__ == "__main__":
    unittest.main()
