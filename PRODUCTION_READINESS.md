# Production-readiness boundary

This project demonstrates how OpenSearch Security Analytics findings can feed
evidence, risk, SecOps, and executive decision workflows. The included examples
are synthetic and must not be represented as production results.

## Capability status

| Capability | Status | Production gate |
|---|---|---|
| Finding normalization | Reference implementation | Live OpenSearch client, schema/version tests and failure handling |
| Governance tag round-trip | Upstream contribution in review | Maintainer review, documentation and merge |
| CRQ output | Preliminary FAIR-inspired estimate | Scenario calibration, distributions, uncertainty and independent review |
| Questionnaire resolver | Synthetic demonstration | Evidence authentication, citations, reviewer workflow and exception handling |
| Revenue attribution | Measurement model | CRM timestamps, attribution policy and Sales/Finance validation |
| Threat emulation | Detector-coverage simulation | Authorized test runner and observed OpenSearch detector results |
| OSCAL and dashboards | Export/template artifacts | Schema validation, data provenance and environment-specific review |

## Claims policy

- The “45 days to 48 hours” result is a target demonstrated with fixtures until
  measured workflow timestamps establish a baseline and outcome.
- Deal or pipeline values are synthetic unless joined to a CRM system of record.
- Pipeline is not recognized revenue. Report raw, probability-weighted, and
  closed-won values separately.
- Technique-count coverage is not material threat-scenario coverage.
- Test-suite success is not evidence of production control operating
  effectiveness.
- Current CRQ calculations are preliminary estimates rather than a validated FAIR
  analysis; alerts do not determine loss frequency or magnitude by themselves.

## Revenue attribution classes

- `observed`: system-of-record blocker and clearance timestamps exist;
- `correlated`: stage movement follows clearance, without proven causation;
- `estimated`: value is modelled with disclosed inputs;
- `synthetic`: test or demonstration data;
- `insufficient_evidence`: required data is missing or stale.

Any board output must display the applicable class and the analysis date.
