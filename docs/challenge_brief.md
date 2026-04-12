# Challenge Brief

Investigate a possible enterprise compromise at Halcyon Meridian Systems after:
- Meridian board and diligence materials were accessed unexpectedly
- a release-engineering hotfix ref behaved strangely
- a sanctioned Box share appeared without request
- export data moved out of a production namespace
- multiple identity, SaaS, cloud, and endpoint alerts fired within the same morning
- a research node later showed CPU spike and coinminer-like traffic

Your job:
- build a phased plan
- normalize timestamps and identify trustworthy anchors
- separate clusters
- determine what is proven vs inferred
- establish scope of impact
- identify root/access paths
- assess data access and exfiltration
- recommend containment, remediation, and follow-up investigation

Constraints:
- not every alert belongs to the same attack
- some suspicious-looking activity is legitimate
- there is at least one unrelated but real incident
- there is at least one stale exercise artifact
- some object-level cloud visibility is incomplete after a point
