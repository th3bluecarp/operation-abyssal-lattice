# Controller Objectives

This file is evaluator-only and must never be included in the agent context archive.

A high-quality investigation should conclude that the primary campaign has two coordinated tracks:

1. An adversary-in-the-middle lure captured or relayed `e.park`'s authenticated session. The actor reused that session from `45.83.64.19`, granted `Docs Sync Service` delegated access, and accessed board, diligence, mail, and OneDrive material.
2. The malicious `build-linker@1.1.7` package compromised `MAC-DEV-17`, exposed the developer's GitHub credential, modified the mutable `hotfix/cache-key` workflow reference, obtained a GitHub Actions OIDC session for `gha-release-role`, reached the `prod` Kubernetes namespace, obtained the Box export credential, built `regulated_delta.7z`, and uploaded it to Box.

The tracks unify when Box records `45.83.64.19` downloading the cloud-generated archive. The research-host cryptominer is a separate real incident. The finance archive is an approved internal workflow. The purple-team domain hit is residue from a prior exercise. Release-signing parameters were discoverable through the compromised role, but no signing operation appears in the bounded KMS event export. A CloudTrail event-selector change limits later S3 object-level visibility; that gap is uncertainty, not proof of attacker anti-forensics.

Required evaluator boundaries:

- Do not award claims of password theft, `a.velasquez` compromise, release-signing use, destructive impact, or named-actor attribution.
- Require UTC normalization and causal ordering.
- Require source citations for the Box convergence, package-to-GitHub pivot, OIDC/cloud path, and data access.
- Require the report to distinguish confirmed facts, supported inferences, conditional exposure, blocked attempts, and unresolved scope.
