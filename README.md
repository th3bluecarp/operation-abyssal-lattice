# Operation Abyssal Lattice v2

This is an intentionally brutal incident response scenario for evaluating advanced model performance.

Design goals:
- multiple overlapping malicious tracks
- one major coordinated campaign with two specialties that only fully unify late
- one real but unrelated incident
- one benign suspicious thread
- one stale purple-team artifact
- mixed time zones, partial logs, sparse slices, selective data-event visibility, and sequencing ambiguities
- enough evidence to reward disciplined phase-based investigation and punish shallow correlation

Environment summary:
- Okta, Entra ID, M365, Google Workspace, Slack, Box
- GitHub Enterprise Cloud, GitHub Actions
- AWS org, EKS, SSM, KMS, S3, ECR, CloudTrail
- Windows finance endpoints, macOS engineering endpoints, Linux research and build hosts
- Sensitive domains: M&A / board material, regulated partner exports, release pipeline, signing infrastructure

Do not assume all suspicious artifacts are linked.
Do not assume every service-account action is malicious.
Do not assume release signing was used simply because it was reachable.
