# Operation Abyssal Lattice — Agentic Grader Instructions

## Grading task

Evaluate the submitted executive post-incident report against `EXECUTIVE_REPORT_RUBRIC.md`, using `GOLDEN_ANSWER_KEY.md` and `controller_objectives.md` as evaluator-only references. The evidence bundle is the source of truth if wording differs.

Do not grade by IOC keyword count. Credit requires a defensible causal chain, UTC-normalized ordering, and citations to supplied artifacts. Accept equivalent artifact paths and reasonable timestamp rounding to the nearest second.

## Required distinctions

The report must distinguish:

- confirmed facts from supported inference;
- the two coordinated tracks of the primary intrusion from three unrelated or benign clusters;
- confirmed data access and exfiltration from possible exposure;
- a blocked MFA attempt from account compromise;
- a telemetry coverage change from proven anti-forensics.

Do not require a threat-actor name, malware-family attribution beyond the observed XMRig evidence, password theft, or exact archive contents beyond the two logged inputs.

## Evidence rules

- Award full timeline points when local `-0700` records are correctly normalized to UTC and causal ordering is preserved. Subsecond precision is optional.
- Accept the Box enterprise CSV's whole-second timestamps and the Box transaction log's millisecond timestamps as the same vendor events.
- Treat `198.51.100.62` as the tokenized prod-main NAT address seen by Box and `10.42.18.23` as the pod/node-side address seen internally.
- Treat the 17:36:01Z `206` as a one-MiB range probe and the 17:36:02Z `200` as the complete 94,513,012-byte download. Do not double-count the probe as a second full exfiltration.
- Attribute `/prod/export/box_token` access to `eks-prod-exporter/partner-export-sync-4k9xv`. The KMS record shows SSM invoking `Decrypt`; the associated SSM management event supplies the workload-role attribution.
- The bounded KMS export contains no `Sign` event. This supports “not proven used,” not proof that signing never occurred outside the supplied scope.

## Scoring procedure

1. Score all eight rubric sections independently.
2. Apply automatic caps before deductions.
3. Apply explicit deductions only once per distinct unsupported conclusion.
4. Never infer missing evidence from writing style or report length.
5. Return a score from 0–100 and concise evidence-based feedback.

## Recommended grader output

```json
{
  "score": 0,
  "section_scores": {
    "executive_conclusion": 0,
    "track_a": 0,
    "track_b": 0,
    "convergence_exfiltration": 0,
    "timeline_sources": 0,
    "independent_clusters": 0,
    "exposure_gaps": 0,
    "response_plan": 0
  },
  "caps_applied": [],
  "deductions": [],
  "strongest_findings": [],
  "material_omissions_or_errors": [],
  "feedback": ""
}
```
