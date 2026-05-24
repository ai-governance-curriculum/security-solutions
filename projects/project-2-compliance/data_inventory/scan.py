"""Scan datasets in S3 + warehouse for PII/PHI; tag accordingly."""
from __future__ import annotations

import json
import re

import pandas as pd


PII_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

PHI_KEYWORDS = {"diagnosis", "patient", "medication", "icd-10", "treatment"}


def classify_dataframe(df: pd.DataFrame, sample_rows: int = 1000) -> dict:
    """Detect PII/PHI signals in a DataFrame; sample to avoid scanning all rows."""
    sampled = df.sample(min(sample_rows, len(df)), random_state=0)

    hits = {"pii": {}, "phi": []}
    for col in sampled.columns:
        for kind, pattern in PII_PATTERNS.items():
            if sampled[col].astype(str).str.contains(pattern, regex=True).any():
                hits["pii"].setdefault(kind, []).append(col)

    column_text = " ".join(sampled.columns).lower()
    for kw in PHI_KEYWORDS:
        if kw in column_text:
            hits["phi"].append(kw)

    classification = ("phi" if hits["phi"]
                       else "pii" if hits["pii"]
                       else "confidential")
    return {"classification": classification, "hits": hits}


if __name__ == "__main__":
    df = pd.DataFrame({"email": ["a@b.com"], "amount": [100]})
    print(json.dumps(classify_dataframe(df), indent=2))
