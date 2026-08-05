# Operation Abyssal Lattice

Operation Abyssal Lattice is an advanced enterprise incident-response evaluation built around identity, SaaS, endpoint, source-control, CI/CD, cloud, Kubernetes, and network evidence.

## Submission boundaries

Do not upload the repository ZIP as agent context. The repository intentionally contains evaluator-only material.

Build the two submission archives with:

```bash
node evaluation/tools/build_distributions.mjs
```

The command validates the dataset and creates:

- `dist/operation-abyssal-lattice-context.zip` — agent-visible forensic evidence only
- `dist/operation-abyssal-lattice-evaluation.zip` — controller objectives, golden answer key, and scoring rubric

Use `ANALYST_PROMPT.md` as the task prompt, the context ZIP as the task context, and the evaluation ZIP for the evaluation-files field. Never give the evaluation ZIP to the task agent.

## Repository layout

- Evidence roots are listed in `evaluation/context_roots.json`.
- `evaluation/` contains hidden generation, validation, grading, and packaging material.
- `telemetry/` contains five seven-day exports totaling more than 35,000 records.
- `GOLDEN_ANSWER_KEY.md` and `EXECUTIVE_REPORT_RUBRIC.md` are evaluator-only even though they remain convenient at repository root.

## Validation

```bash
node evaluation/tools/generate_weekly_telemetry.mjs
node evaluation/tools/validate_dataset.mjs
node evaluation/tools/build_distributions.mjs
```

The validator checks parsing, answer leakage, event distributions, DNS consistency, stable hashes, platform/process compatibility, HTTP semantics, chronology, Kubernetes validity, Box causality, and cross-source reconciliation.
