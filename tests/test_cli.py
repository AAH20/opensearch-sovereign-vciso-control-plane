"""Unit tests for CLI subcommands."""

import json
from pathlib import Path
import subprocess
import sys
import unittest

PROJECT_ROOT = Path(__file__).parents[1]


class TestCLI(unittest.TestCase):
    def run_cli(self, args: list[str]) -> subprocess.CompletedProcess:
        cmd = [sys.executable, "-m", "opensearch_vciso.cli"] + args
        return subprocess.run(
            cmd,
            cwd=PROJECT_ROOT,
            env={"PYTHONPATH": str(PROJECT_ROOT / "src")},
            capture_output=True,
            text=True,
        )

    def test_cli_crq(self) -> None:
        res = self.run_cli(["crq", "examples/finding-lsass-dump.json"])
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertEqual(data["finding_id"], "FINDING-OPENSEARCH-SEC-9021")
        self.assertEqual(data["asset_criticality"], "TIER_0")
        self.assertEqual(data["single_loss_expectancy_usd"], 4375000.0)

    def test_cli_soc_yield(self) -> None:
        res = self.run_cli(["soc-yield", "examples/soc-telemetry.json"])
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertEqual(data["l1_total_alerts_triaged"], 1450)
        self.assertEqual(data["economic_yield_status"], "HIGH_YIELD")

    def test_cli_revenue_enable(self) -> None:
        res = self.run_cli(["revenue-enable", "examples/vendor-security-questionnaire.json"])
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertEqual(data["resolution_status"], "COMPLETED_AND_ATTESTED")
        self.assertEqual(data["total_questions_resolved"], 4)

    def test_cli_emulate_threat(self) -> None:
        res = self.run_cli(["emulate-threat", "examples/adversary-emulation-apt29.json"])
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertEqual(data["detection_efficacy_percentage"], 100.0)
        self.assertEqual(data["detected_techniques_count"], 4)

    def test_cli_board_memo(self) -> None:
        res = self.run_cli(["board-memo"])
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("EXECUTIVE DECISION MEMORANDUM", res.stdout)

    def test_cli_export_oscal(self) -> None:
        res = self.run_cli(["export-oscal"])
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertIn("system-security-plan", data)


if __name__ == "__main__":
    unittest.main()
