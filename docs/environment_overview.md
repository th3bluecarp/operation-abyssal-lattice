# CMDB and Identity Directory Extract

Export captured 2026-03-13T14:00:00Z. Display names are omitted from this collection.
The people and host sections are the case-custodian subset requested at collection time; weekly telemetry also contains uncustodied enterprise assets.

## People
- e.park — executive assistant to CFO
- a.velasquez — director of corp dev
- r.kapoor — senior platform engineer
- t.owens — release engineering lead
- m.sato — finance analyst
- j.mercer — research contractor
- l.chen — secops analyst
- n.byrd — DevEx engineer

## Hosts
- FIN-WS22 (Windows)
- FIN-WS31 (Windows)
- MAC-DEV-17 (macOS)
- MAC-DEV-04 (macOS)
- BLD-RUN-02 (Linux build runner)
- RSCH-JUP-03 (Linux research/Jupyter)
- ip-10-42-18-23 (EKS node)
- ip-10-42-18-41 (EKS node)

## Service ownership
- CorpDev SharePoint and Box folders — Corporate Development
- release-orchestrator and actions-infra — Release Engineering
- prod-main EKS cluster — Platform Engineering
- RSCH-JUP-03 — Research Computing
- FIN-WS22 and FIN-WS31 — Finance IT

## Network ranges
- 10.24.18.0/24 — Finance workstations
- 10.88.44.0/24 — Engineering VPN clients
- 10.42.18.0/24 — prod-main EKS nodes and pods
- 10.55.72.0/24 — Research Computing
- 10.3.8.0/24 — Security tooling
- 10.8.4.0/24 — CI build runners
- 10.8.12.0/24 — Operations workstations and services
- 10.31.9.0/24 — Human Resources workstations
- 10.42.7.0/24 — Sales workstations

## Egress addresses
- 198.51.100.10 — employee office internet egress (tokenized in this export)
- 198.51.100.62 — prod-main workload NAT egress (tokenized in this export)
