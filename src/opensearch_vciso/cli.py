"""Command Line Interface for OpenSearch Sovereign vCISO Control Plane."""

import argparse
import json
from pathlib import Path
import sys

from .models import SecurityFinding, QuestionnaireItem
from .crq import CyberRiskQuantifier
from .grc_revenue import GRCRevenueEngine, TrustVault
from .soc_yield import SOCYieldEngine
from .threat_emulation import ThreatEmulationEngine
from .board_memo import BoardMemoGenerator


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OpenSearch Sovereign vCISO & Cyber Risk Quantification Control Plane"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1. crq
    crq_parser = subparsers.add_parser("crq", help="Quantify financial cyber risk (FAIR model) from an OpenSearch finding")
    crq_parser.add_argument("finding", help="Path to OpenSearch security finding JSON")
    crq_parser.add_argument("--output", help="Optional output path")

    # 2. soc-yield
    soc_parser = subparsers.add_parser("soc-yield", help="Calculate SOC Analyst Tier KPIs (L1-L3) and Unit Economics")
    soc_parser.add_argument("telemetry", help="Path to SOC operational telemetry JSON")
    soc_parser.add_argument("--output", help="Optional output path")

    # 3. revenue-enable
    rev_parser = subparsers.add_parser("revenue-enable", help="Auto-resolve enterprise vendor questionnaire via Trust Vault")
    rev_parser.add_argument("questionnaire", help="Path to inbound vendor questionnaire JSON")
    rev_parser.add_argument("--output", help="Optional output path")

    # 4. emulate-threat
    emu_parser = subparsers.add_parser("emulate-threat", help="Run adversary threat emulation and validate detection efficacy")
    emu_parser.add_argument("scenario", help="Path to threat emulation scenario JSON")
    emu_parser.add_argument("--output", help="Optional output path")

    # 5. board-memo
    memo_parser = subparsers.add_parser("board-memo", help="Generate Executive Board of Directors Decision Memorandum")
    memo_parser.add_argument("--output", help="Optional output markdown file path")

    # 6. export-oscal
    oscal_parser = subparsers.add_parser("export-oscal", help="Export NIST OSCAL System Security Plan JSON")
    oscal_parser.add_argument("--org", default="A2Z-Enterprise-Defense", help="Organization name")
    oscal_parser.add_argument("--output", help="Optional output path")

    # Support default behavior if first arg is a finding JSON file
    raw_args = sys.argv[1:]
    if raw_args and not raw_args[0].startswith("-") and raw_args[0] not in (
        "crq", "soc-yield", "revenue-enable", "emulate-threat", "board-memo", "export-oscal"
    ):
        raw_args = ["crq"] + raw_args

    args = parser.parse_args(raw_args)

    if args.command == "crq":
        raw = json.loads(Path(args.finding).read_text())
        finding = SecurityFinding(
            finding_id=raw["finding_id"],
            detector_id=raw["detector_id"],
            rule_name=raw["rule_name"],
            severity=raw["severity"],
            mitre_technique=raw["mitre_technique"],
            target_asset_id=raw["target_asset_id"],
            timestamp=raw.get("timestamp", "2026-09-04T05:00:00Z"),
            raw_telemetry=raw.get("raw_telemetry", {}),
        )
        quantifier = CyberRiskQuantifier()
        result = quantifier.quantify_finding(finding)
        rendered = json.dumps(result.__dict__, indent=2, sort_keys=True)
        if args.output:
            Path(args.output).write_text(rendered + "\n")
        else:
            print(rendered)

    elif args.command == "soc-yield":
        telemetry = json.loads(Path(args.telemetry).read_text())
        engine = SOCYieldEngine()
        metrics = engine.calculate_yield(telemetry)
        rendered = json.dumps(metrics.__dict__, indent=2, sort_keys=True)
        if args.output:
            Path(args.output).write_text(rendered + "\n")
        else:
            print(rendered)

    elif args.command == "revenue-enable":
        raw = json.loads(Path(args.questionnaire).read_text())
        questions = [
            QuestionnaireItem(
                item_id=q["item_id"],
                question=q["question"],
                category=q.get("category", "security"),
                framework_mapping=q.get("framework_mapping", ["SOC2"]),
            )
            for q in raw.get("questions", [])
        ]
        vault = TrustVault()
        engine = GRCRevenueEngine(vault)
        answers = engine.resolve_questionnaire(questions)
        output_payload = {
            "vendor_questionnaire_id": raw.get("questionnaire_id", "VENDOR-REQ-2026-09"),
            "customer_name": raw.get("customer_name", "Fortune 100 Enterprise"),
            "resolution_status": "COMPLETED_AND_ATTESTED",
            "total_questions_resolved": len(answers),
            "answers": [a.__dict__ for a in answers],
        }
        rendered = json.dumps(output_payload, indent=2, sort_keys=True)
        if args.output:
            Path(args.output).write_text(rendered + "\n")
        else:
            print(rendered)

    elif args.command == "emulate-threat":
        raw = json.loads(Path(args.scenario).read_text())
        registered = [
            "detector-lsass-memory-dump",
            "detector-ransomware-mass-encryption",
            "detector-iam-stolen-keys",
            "detector-smb-lateral-movement",
        ]
        engine = ThreatEmulationEngine(registered)
        report = engine.run_scenario(raw)
        rendered = json.dumps({
            "scenario_id": report.scenario_id,
            "adversary_profile": report.adversary_profile,
            "total_techniques_tested": report.total_techniques_tested,
            "detected_techniques_count": report.detected_techniques_count,
            "detection_efficacy_percentage": report.detection_efficacy_percentage,
            "avg_detection_latency_ms": report.avg_detection_latency_ms,
            "blindspot_drift_detected": report.blindspot_drift_detected,
            "results": [r.__dict__ for r in report.results],
            "timestamp": report.timestamp,
        }, indent=2, sort_keys=True)
        if args.output:
            Path(args.output).write_text(rendered + "\n")
        else:
            print(rendered)

    elif args.command == "board-memo":
        generator = BoardMemoGenerator()
        memo = generator.generate_memo(
            crq_summary={"total_value_at_risk_usd": 4_375_000.0, "total_ale_usd": 218_750.0, "overall_mitigation_roi": 182.5},
            grc_summary={"overall_compliance_percentage": 100.0, "unblocked_enterprise_pipeline_usd": 8_400_000.0},
            soc_summary={"cost_per_true_positive_usd": 58.40, "l1_signal_to_noise_ratio": 0.15, "l2_mean_time_to_respond_minutes": 22.5},
            emulation_summary={"detection_efficacy_percentage": 92.5},
        )
        if args.output:
            Path(args.output).write_text(memo + "\n")
        else:
            print(memo)

    elif args.command == "export-oscal":
        vault = TrustVault()
        engine = GRCRevenueEngine(vault)
        oscal = engine.export_oscal_ssp(organization_name=args.org)
        rendered = json.dumps(oscal, indent=2, sort_keys=True)
        if args.output:
            Path(args.output).write_text(rendered + "\n")
        else:
            print(rendered)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
