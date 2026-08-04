# Abyssal Lattice: Post-Incident Executive Analysis Prompt

You are the lead incident responder for Halcyon Meridian Systems. Using only the evidence in this repository, produce a defensible post-incident analysis for executives and the board.

Your deliverable must:

1. Normalize timestamps into UTC. Explicitly account for Windows/macOS `-0700` offsets, the approximately 92-second RSCH-JUP-03 clock drift, Zeek timestamp limitations, and possible Box/proxy audit lag.
2. Establish trustworthy anchors and build a phased timeline: initial access, identity/session abuse, developer/package compromise, source-control/CI activity, cloud/EKS activity, data movement, discovery/response, and the later research-host incident.
3. Separate the evidence into distinct clusters before deciding what, if anything, unifies them. For every material claim, cite the source path, timestamp, actor/host, and confidence (confirmed, strongly supported, possible, unresolved, or disproven).
4. Determine the primary campaign's access paths, persistence, privilege changes, affected identities/devices, sensitive data accessed, exfiltration path, and blast radius. Distinguish access from download and download from confirmed external receipt.
5. Explain the late unifying pivot: the cloud-generated Box artifact was externally downloaded by the same IP that drove the SaaS abuse.
6. Classify the research-node CPU/coinminer activity as a real but unrelated incident, the finance archiving workflow as benign and approved, and the in-window purple-team beacon as stale exercise residue.
7. Assess release-signing exposure carefully: reachable credentials or signing infrastructure are exposure, not proof that release signing was used.
8. Treat the approximately 10:48Z data-event visibility change as an uncertainty and telemetry gap, not proof of anti-forensics without supporting evidence.
9. End with executive impact, business risk, containment already indicated by the evidence, prioritized remediation, recovery/validation steps, and a 30/60/90-day follow-up plan.

Do not invent identities, IPs, files, commands, exfiltrated objects, attribution, or dates. Do not collapse every alert into one intrusion. Do not use absence of an event as proof that it did not happen where visibility is incomplete. Quote exact values only when present in the artifacts.
