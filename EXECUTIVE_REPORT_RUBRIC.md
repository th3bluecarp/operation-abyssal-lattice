# Abyssal Lattice Executive Report Rubric

## Required content (must be present)

- Executive summary with affected business assets, confidence, material business impact, and the primary campaign versus unrelated activity.
- UTC-normalized timeline with source citations and explicit handling of all documented clock/audit caveats.
- Two primary coordinated tracks: (A) AiTM/session theft and OAuth-consent abuse against `e.park`; (B) malicious package/developer compromise -> GitHub hotfix-ref abuse -> CI/OIDC -> AWS -> EKS -> export -> Box.
- Exact initial-access details: `review-board-portal.com/session/84e2`, `FIN-WS22`, `45.83.64.19`, `Docs Sync Service`, and delegated scopes `Files.Read.All`, `Mail.Read`, and `offline_access`.
- Exact supply-chain/cloud details: `build-linker`, `MAC-DEV-17`, `r.kapoor`, `hotfix/cache-key`, GitHub Actions OIDC, `gha-release-role`, `/prod/export/box_token`, and `regulated_delta.7z`.
- The exact late correlation that unifies the tracks: the cloud-generated Box artifact is downloaded externally by the same IP driving the SaaS abuse.
- Separate findings for the unrelated RSCH-JUP-03 coinminer, approved finance archive workflow, and stale purple-team beacon.
- Access/persistence/privilege/data-access/exfiltration/blast-radius analysis with confidence labels and evidence paths.
- Explicit statement that release-signing access is exposed but signing use is not proven.
- Explicit statement that `a.velasquez` denied the MFA challenge and is targeted, not confirmed compromised.
- Explicit statement that the data-event visibility change around 10:48Z creates uncertainty and is not, alone, anti-forensics.
- Containment, eradication, recovery, notification/legal considerations, and prioritized owners/actions.

## Scoring

- 30% timeline and time normalization
- 25% correct clustering and late unification
- 20% scope, impact, and exfiltration precision
- 15% treatment of false signals and uncertainty
- 10% actionable executive remediation and communication

## Must not appear

- A claim that all alerts belong to one campaign.
- A claim that the coinminer, finance archive, or purple-team beacon is part of the primary campaign.
- A claim that release signing was used merely because signing secrets/infrastructure were reachable.
- A claim that the 10:48Z visibility gap proves log deletion or anti-forensics.
- Unsupported attribution, invented timestamps, guessed file contents, or fabricated observables.
- “No evidence” phrased as “evidence of no activity” when the repository documents selective or missing visibility.
- A cross-tenant or organization-wide impact claim without identifying the supporting artifacts.

## Quality bar

Every high-impact conclusion must be traceable to at least two independent artifacts where available. The report must distinguish confirmed fact, inference, conditional possibility, blocked chain, and unresolved question, and must preserve exact usernames, hosts, IPs, object names, and timestamps from the evidence.
