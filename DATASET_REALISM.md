# Dataset realism and provenance

The scenario uses synthetic identities and safe documentation/test networks, but its records follow the conventions and causal relationships of the represented systems. The agent context contains 71 files. Five large weekly exports contain more than 35,000 records with realistic long-tail activity, recurring identities and source addresses, domain-consistent DNS answers, OS-appropriate processes, stable per-binary hashes, varied HTTP methods/statuses, and common OAuth/OIDC events that match the shape of the relevant incident events.

Curated evidence is cross-source consistent: local-offset and UTC times reconcile; Zeek epochs decode to the incident date; CloudTrail follows the command that generated it; Kubernetes jobs precede their pods and logs; SSM/KMS roles align; archive creation precedes upload, link creation, and download; and NetFlow byte totals reconcile with Zeek.

Generator and validation logic lives under `evaluation/tools/` and is intentionally excluded from agent context. No generation timestamps, deterministic seeds, answer keys, IOC checklists, controller objectives, prebuilt timelines, or dataset labels are included in the context archive.
