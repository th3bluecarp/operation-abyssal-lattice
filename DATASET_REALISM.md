# Dataset realism and provenance

The scenario is fictional and uses documentation-only IP ranges, but the artifacts are intended to be operationally parseable. Core records use the conventions of the source systems: CSV exports, JSONL audit events, unified diffs, Sysmon-style CSV, proxy lines, Kubernetes audit JSONL, and Box transaction logs. The `telemetry/` corpus covers seven days and contains more than 15,000 records with the malicious activity embedded among ordinary business traffic.

The `noise/` directory contains compact, multi-event benign background excerpts to test clustering. They are synthetic and should not be mistaken for a complete production log archive. The high-value evidence is corroborated across independent sources rather than relying on a single planted line.

Known limitations remain explicit: no claim is made that the repository contains a real packet capture, real customer data, or vendor-native proprietary databases. The investigation prompt must treat missing telemetry as uncertainty.

The corpus is deterministically regenerated with `node tools/generate_weekly_telemetry.mjs` and checked with `bash tools/validate_dataset.sh`.
