# RFC: FAIR-Aligned Cyber Risk Quantification (CRQ) and Financial Loss Attribution for OpenSearch Security Analytics Alerts

**RFC ID**: RFC-2026-SEC-ANALYTICS-CRQ-01  
**Author**: Ahmed Hassan ([@AAH20](https://github.com/AAH20))  
**Target Component**: `opensearch-project/security-analytics`  
**Status**: PROPOSED  
**Created**: September 4, 2026  

---

## 1. Executive Summary & Problem Statement
Currently, `opensearch-project/security-analytics` generates alert findings containing technical attributes:
- `detector_id`
- `severity` (CRITICAL, HIGH, MEDIUM, LOW)
- `mitre_techniques`
- `triggers`

While essential for SOC triage engineers, technical severities fail to communicate business risk to Chief Information Security Officers (CISOs), Chief Financial Officers (CFOs), and Corporate Boards. A "CRITICAL" finding on an ephemeral test VM carries radically different financial exposure than a "MEDIUM" finding on an enterprise Stripe transactional database cluster.

This RFC proposes introducing native **Cyber Risk Quantification (CRQ)** metadata fields based on the international **FAIR (Factor Analysis of Information Risk)** standard directly into the OpenSearch Security Analytics alert finding schema.

---

## 2. Proposed Data Schema Extension
We propose enriching the OpenSearch finding index mapping (`.opensearch-sap-finding*`) with an optional `cyber_risk_quantification` object:

```json
{
  "finding_id": "FINDING-9021",
  "detector_id": "detector-lsass-memory-dump",
  "severity": "CRITICAL",
  "mitre_technique": "T1003.001",
  "target_asset": {
    "asset_id": "asset-stripe-billing-db",
    "criticality_tier": "TIER_0",
    "asset_valuation_usd": 12500000.00
  },
  "cyber_risk_quantification": {
    "framework": "FAIR-v3",
    "single_loss_expectancy_usd": 4375000.00,
    "annual_rate_of_occurrence": 0.05,
    "annualized_loss_expectancy_usd": 218750.00,
    "value_at_risk_95_usd": 1600000.00,
    "recommended_mitigation_cost_usd": 450.00,
    "mitigation_roi_ratio": 486.1,
    "currency": "USD"
  }
}
```

---

## 3. Core Mathematical Implementation
1. **Single Loss Expectancy (SLE)**:
   $$\text{SLE} = \text{Asset Valuation} \times \text{Exposure Factor (EF)}$$
   Where $\text{Exposure Factor}$ is derived from the cross-product of `Asset Criticality Tier` and detector `Severity`.

2. **Annualized Loss Expectancy (ALE)**:
   $$\text{ALE} = \text{Annual Rate of Occurrence (ARO)} \times \text{SLE}$$

3. **Value at Risk ($\text{VaR}_{95\%}$)**:
   Bounds the tail 95th-percentile financial exposure across correlated security incidents.

4. **Remediation Economic ROI Ratio**:
   $$\text{ROI} = \frac{\text{ALE}}{\text{Mitigation Cost}}$$

---

## 4. Architectural Integration with OpenSearch Stack
- **Ingestion & Alerting Pipeline**:
  - The Security Analytics alerting engine reads asset metadata from an indexed asset catalog (`.opensearch-asset-catalog`).
  - Upon detector execution, the alerting worker computes CRQ fields in real time without Lucene indexing lag.
- **OpenSearch Dashboards**:
  - Adds a pre-built **C-Suite & Board Executive View** summarizing Total Dollars-at-Risk across the enterprise fleet.

---

## 5. Backward Compatibility & Performance Impact
- The `cyber_risk_quantification` field is purely additive and optional. Existing detectors without asset catalog mappings will default to standard severity scoring.
- The mathematical evaluation adds `< 0.05ms` compute overhead per generated finding, retaining sub-second real-time alert latency.
