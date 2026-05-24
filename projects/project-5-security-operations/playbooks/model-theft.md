# Playbook — Model Theft Detection

## Trigger
Sigma rule `model-extraction.yml` fires: user > 10K queries / hour with > 95% input diversity.

## Severity assessment (first 5 min)
- Confirm user identity exists + is in expected pool
- Check `user.tag` for `load_test=true` (whitelist)
- Check current rate vs historical baseline (3× normal = suspect)
- Review query content (random vs structured)

## Immediate response (5-15 min)
1. **Rate limit** the user via API gateway (block at 60/min)
2. **Notify** user on-call lead + security on-call
3. **Pull query logs** for forensics (last 24h)

## Investigation (15-60 min)
- Cross-reference with auth events (compromised account?)
- Check for: distillation attack pattern, model-stealing attack (Shokri 2017)
- If confirmed: revoke API key; rotate all credentials for that team

## Remediation
- If model was likely extracted: bump watermark version; consider model rotation
- If account was compromised: full credential rotation + audit access to other resources
- File incident ticket; postmortem within 1 week

## Companion
[engineer-solutions/mod-108 ex-09 POSTMORTEM_TEMPLATE.md](https://github.com/ai-infra-curriculum/ai-infra-engineer-solutions/blob/main/modules/mod-108-monitoring-observability/exercise-09-incident-response-gameday/POSTMORTEM_TEMPLATE.md)
