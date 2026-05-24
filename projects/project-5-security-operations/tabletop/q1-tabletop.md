# Q1 2026 Tabletop — ML SOC

## Format
- 2h session, 8 participants (SRE, ML platform, security, product on-call)
- Facilitator presents scenario; participants respond as they would in real incident
- Document gaps; convert to action items

## Scenario A — Model Theft (45 min)
A junior data scientist's API key has been used in the past 6 hours to query
the production fraud-detection model at 50K queries/hour from an IP in
Belarus. The user is on PTO in Hawaii.

Questions:
- What's the first thing you do?
- Who needs to know in the first hour?
- How do you know if the model was actually extracted?
- What do you tell legal?
- What changes after the incident?

## Scenario B — Data Poisoning (45 min)
The nightly model retrain produced a model with 30% accuracy regression on
the protected demographic A. The training data ingestion was modified 2 weeks
ago to include a new vendor feed.

Questions:
- Roll back the retrained model? (yes/no — why)
- How do you quarantine the new vendor feed?
- How do you reconstruct what happened?
- When do you notify the vendor?

## Scenario C — Insider Privilege Abuse (30 min)
A senior platform engineer has access to all model registries + Vault. They've
started exporting model artifacts to a personal S3 bucket. Slack messages
suggest they're leaving to a competitor.

Questions:
- Immediate technical response?
- HR + Legal coordination?
- Post-incident credential rotation scope?

## Synthesis
- Top 3 gaps identified across scenarios
- Action items with owner + due date
- Schedule Q2 tabletop with new scenarios
