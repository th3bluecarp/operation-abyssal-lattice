# Evidence Collection Scope

Collection ID: HM-IR-2026-0313
Collection opened: 2026-03-13T20:05:00Z
Primary review window: 2026-03-09T00:00:00Z through 2026-03-16T00:00:00Z

Sources acquired:

- Okta System Log, Entra sign-ins, VPN concentrator
- Microsoft 365 unified audit, Google Workspace Drive audit, Box enterprise events
- GitHub enterprise audit, repository snapshots, GitHub Actions job output
- AWS organization CloudTrail exports and EKS Kubernetes audit
- EDR and selected native endpoint logs
- corporate DNS, secure web gateway, Zeek, Suricata, and summarized NetFlow

Timestamp handling:

- SaaS and cloud exports use UTC unless a field states otherwise.
- Windows `UtcTime` fields use UTC.
- Browser history and Apple unified-log excerpts retain their recorded `-0700` offset.
- Linux syslog excerpts use the host's configured America/Los_Angeles timezone.

Collection notes:

- Large weekly exports are included alongside smaller case pivots.
- Network capture retention had expired before collection; no packet payload archive was available.
- Some vendor exports use request-start timestamps while others use completion or audit-publication timestamps.
- Known employee residential and office egress addresses were tokenized into documentation ranges during legal export; unknown third-party addresses were retained.
