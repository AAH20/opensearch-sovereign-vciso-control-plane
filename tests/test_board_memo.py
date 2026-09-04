"""Unit tests for Board Memo generator."""

import unittest
from opensearch_vciso.board_memo import BoardMemoGenerator


class TestBoardMemo(unittest.TestCase):
    def test_generate_memo_content(self) -> None:
        generator = BoardMemoGenerator()
        memo = generator.generate_memo(
            crq_summary={"total_value_at_risk_usd": 5_000_000.0, "total_ale_usd": 250_000.0, "overall_mitigation_roi": 150.0},
            grc_summary={"overall_compliance_percentage": 100.0, "unblocked_enterprise_pipeline_usd": 10_000_000.0},
            soc_summary={"cost_per_true_positive_usd": 45.0, "l1_signal_to_noise_ratio": 0.18, "l2_mean_time_to_respond_minutes": 20.0},
            emulation_summary={"detection_efficacy_percentage": 95.0},
            organization_name="Test Enterprise Corp",
        )
        self.assertIn("EXECUTIVE DECISION MEMORANDUM", memo)
        self.assertIn("$5,000,000.00", memo)
        self.assertIn("$10,000,000.00", memo)
        self.assertIn("Test Enterprise Corp", memo)
        self.assertIn("150.0x Loss Avoidance", memo)
        self.assertIn("DATA CLASSIFICATION: SYNTHETIC", memo)

    def test_rejects_unknown_data_classification(self) -> None:
        generator = BoardMemoGenerator()
        with self.assertRaises(ValueError):
            generator.generate_memo({}, {}, {}, {}, data_classification="production-ish")


if __name__ == "__main__":
    unittest.main()
