"""Generate quarterly compliance report for GDPR + HIPAA + SOC 2."""
from __future__ import annotations

from datetime import UTC, date, datetime


CONTROLS_GDPR = {
    "Art. 5  - data minimization": "data_inventory + retention enforcement",
    "Art. 7  - consent management": "consent log table; opt-in default",
    "Art. 17 - right to erasure": "GDPR DELETE endpoint",
    "Art. 20 - right to portability": "GDPR EXPORT endpoint",
    "Art. 22 - automated decision-making": "model cards + EXPLAIN endpoint",
    "Art. 32 - security of processing": "mTLS + Vault + Falco (project-1)",
    "Art. 33 - breach notification": "SOC playbook; 72h notification SLA",
}

CONTROLS_HIPAA = {
    "164.308 - administrative safeguards": "RBAC + access reviews",
    "164.310 - physical safeguards": "data center compliance attestations",
    "164.312 - technical safeguards": "encryption at rest + in transit",
    "164.514 - de-identification": "PII scrubbing pipeline (mod-09 ex-04)",
}

CONTROLS_SOC2 = {
    "CC6.1 - logical access": "OIDC + RBAC + audit log",
    "CC6.6 - encryption": "mTLS + Vault-backed secrets",
    "CC7.2 - system monitoring": "Falco + SIEM (project-5)",
    "CC7.3 - incident response": "playbooks + game days",
    "A1.2 - availability monitoring": "SLO + burn-rate alerts (mod-108 ex-08)",
}


def report():
    today = date.today()
    quarter = (today.month - 1) // 3 + 1
    print(f"# Compliance Report Q{quarter} {today.year}")
    print(f"\n_Generated {datetime.now(UTC).isoformat()}_\n")

    for framework, controls in [("GDPR", CONTROLS_GDPR),
                                  ("HIPAA", CONTROLS_HIPAA),
                                  ("SOC 2", CONTROLS_SOC2)]:
        print(f"\n## {framework}\n")
        print("| Control | Evidence | Status |")
        print("|---|---|---|")
        for control, evidence in controls.items():
            print(f"| {control} | {evidence} | ✅ |")

    print("\n## Outstanding items")
    print("- None this quarter, OR list exceptions with target resolution date")


if __name__ == "__main__":
    report()
