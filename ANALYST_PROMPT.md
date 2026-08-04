# Abyssal Lattice: Post-Incident Executive Analysis Prompt

You are a cybersecurity analyst investigating a potential breach at Halcyon Meridian Systems. Analyze the collected artifacts in this repository and produce a defensible post-incident executive report.

Create a normalized timeline of relevant events and explain the evidence-supported intrusion story, including every initial access path, pivot, persistence mechanism, privilege change, affected identity or host, sensitive-data access, exfiltration path, and resulting business impact. Separate independent incidents and benign activity where the evidence supports doing so.

For each important conclusion, cite the artifact and timestamp, distinguish fact from inference, and identify gaps or conflicting evidence. Account for timestamp and telemetry limitations. End with prioritized containment, remediation, recovery, notification, and follow-up recommendations for executive decision-makers.

Use only evidence present in the repository. Do not invent observables, attribution, or certainty, and do not assume that every alert belongs to the same intrusion.
