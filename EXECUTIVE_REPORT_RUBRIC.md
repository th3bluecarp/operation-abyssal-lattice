# Operation Abyssal Lattice — Executive Report Rubric

Score out of 100. Award only evidence-supported claims with artifact citations. A polished narrative cannot recover points for an incorrect intrusion chain.

## 1. Executive conclusion and business impact — 12 points

- **4:** States one coordinated primary campaign with two initially separate tracks that converge at Box.
- **3:** Identifies confidentiality impact to board/Meridian diligence material and the regulated partner export.
- **3:** Gives calibrated confidence and distinguishes confirmed impact from possible exposure.
- **2:** Uses executive language while preserving exact affected identities/assets.

## 2. Track A: identity, OAuth, and SaaS — 18 points

- **4:** Identifies the `review-board-portal.com/session/84e2` AiTM lure on `FIN-WS22` and cites email/browser plus endpoint/network evidence.
- **4:** Identifies session reuse from `45.83.64.19`; does not overclaim password theft.
- **4:** Identifies unverified `Docs Sync Service` and scopes `Files.Read.All`, `Mail.Read`, and `offline_access` as OAuth persistence/access.
- **4:** Names the exact board, valuation, mail, OneDrive, and Drive access supported by the SaaS records.
- **2:** Treats the 15:26:44Z `a.velasquez` denial as a blocked attempt, not compromise.

## 3. Track B: package through cloud workload — 24 points

- **4:** Identifies `build-linker@1.1.7` postinstall execution on `MAC-DEV-17` and reconciles registry/install evidence.
- **4:** Identifies GitHub credential access/staging and `com.apple.sync` LaunchAgent persistence without inventing a full token value.
- **4:** Identifies the temporary deploy key and `hotfix/cache-key` push from `203.0.113.71`, plus missing protection for that ref.
- **4:** Explains the malicious reusable-workflow change, approval, run 8841, OIDC issuance, and `gha-release-role` assumption.
- **4:** Correctly orders kubeconfig access, `prod` job/pod creation, `prod:release-exporter`, IRSA `eks-prod-exporter`, and Box-token retrieval.
- **4:** Identifies `customer_delta.parquet`, `partner_map.csv`, and creation of `regulated_delta.7z` without claiming unlogged contents.

## 4. Convergence and confirmed exfiltration — 12 points

- **5:** Uses the 17:36:02Z Box download of `regulated_delta.7z` from `45.83.64.19` as the decisive cross-track correlation.
- **3:** Correctly orders upload completion (17:34:44Z), open-link creation (17:35:10Z), and external download.
- **2:** Reconciles the 94,513,012-byte object and 99,514,862-byte network flow without calling protocol overhead a contradiction.
- **2:** Calls exfiltration confirmed rather than merely staged or attempted.

## 5. Timeline and source handling — 10 points

- **4:** Normalizes `-0700` endpoint/browser times to UTC and keeps the incident on Friday 2026-03-13.
- **2:** Uses correct Zeek epochs and aligns Zeek/Suricata/NetFlow records.
- **2:** Preserves request/start versus completion/publication semantics where relevant.
- **2:** Cites artifacts and timestamps for every material pivot.

## 6. Independent and benign clusters — 10 points

- **4:** Separates the real `RSCH-JUP-03` XMRig incident and correctly identifies `j.mercer`, root, PID 2311, `/tmp/xmrig`, and `192.0.2.77:3333`.
- **3:** Separates the approved FIN-1842 `board_packets.7z` internal-share workflow.
- **3:** Separates the PT-07 purple-team replay using the February calendar/file/systemd evidence.

## 7. Exposure, gaps, and prohibited overreach — 7 points

- **3:** States signing parameters were reachable under `/prod/*`, but no supplied KMS/workflow record proves `Sign` usage.
- **2:** Treats the 17:18:07Z event-selector change as a coverage gap and does not attribute it to the attacker without evidence.
- **2:** Distinguishes fact, inference, conditional exposure, blocked action, and unresolved question.

## 8. Response plan — 7 points

- **3:** Immediate identity/OAuth, endpoint, GitHub/workflow/OIDC, cloud, Kubernetes, Box-link, and secret containment.
- **2:** Separate containment and rebuild for `RSCH-JUP-03`.
- **2:** Prioritized long-term controls: immutable workflow pinning/branch coverage, package provenance/lifecycle isolation, least-privilege OIDC/SSM, OAuth governance, and CloudTrail data-event retention.

## Automatic caps and deductions

- **Maximum 50:** Misses either primary track or says the tracks are unrelated.
- **Maximum 60:** Fails to identify the Box/IP convergence or says exfiltration is unproven.
- **Maximum 70:** Includes no normalized timeline or material artifact citations.
- **Minus 10 each:** Claims `a.velasquez` compromise, release-signing use, or anti-forensic attribution as fact.
- **Minus 8 each:** Merges the miner, finance workflow, or PT-07 replay into the primary campaign.
- **Minus 5 each:** Claims password theft, `t.owens` complicity, destructive/ransomware impact, tenant-wide access, or named threat-actor attribution without evidence.
- Never reduce below zero.
