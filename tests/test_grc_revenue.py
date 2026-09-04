"""Unit tests for GRC Revenue Enablement and Trust Vault."""

import unittest
from opensearch_vciso.models import QuestionnaireItem
from opensearch_vciso.grc_revenue import GRCRevenueEngine, TrustVault


class TestGRCRevenue(unittest.TestCase):
    def setUp(self) -> None:
        self.vault = TrustVault()
        self.engine = GRCRevenueEngine(self.vault)

    def test_trust_vault_compliance_score(self) -> None:
        score = self.vault.get_compliance_score()
        self.assertEqual(score["overall_compliance_percentage"], 100.0)
        self.assertEqual(score["verified_controls"], score["total_controls_tracked"])

    def test_resolve_vendor_questionnaire(self) -> None:
        questions = [
            QuestionnaireItem(
                item_id="Q-01",
                question="Do you enforce Multi-Factor Authentication (MFA)?",
                category="access_control",
                framework_mapping=["SOC2-CC6.1"],
            ),
            QuestionnaireItem(
                item_id="Q-02",
                question="Is customer data encrypted in transit using TLS 1.3?",
                category="encryption",
                framework_mapping=["SOC2-CC6.7"],
            ),
            QuestionnaireItem(
                item_id="Q-03",
                question="What is the RTO/RPO disaster recovery guarantee under DORA?",
                category="business_continuity",
                framework_mapping=["DORA-ART-9"],
            ),
        ]
        answers = self.engine.resolve_questionnaire(questions)
        self.assertEqual(len(answers), 3)
        self.assertTrue(all(a.status == "VERIFIED" for a in answers))
        self.assertIn("FIPS 140-3 MFA", answers[0].answer_text)
        self.assertIn("TLS 1.3", answers[1].answer_text)
        self.assertIn("RTO < 15 minutes", answers[2].answer_text)

    def test_export_oscal_ssp(self) -> None:
        oscal = self.engine.export_oscal_ssp(organization_name="Enterprise-Bank")
        self.assertIn("system-security-plan", oscal)
        plan = oscal["system-security-plan"]
        self.assertEqual(plan["metadata"]["oscal-version"], "1.0.4")
        self.assertGreater(len(plan["control-implementation"]["implemented-requirements"]), 4)


if __name__ == "__main__":
    unittest.main()
