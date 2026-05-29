Split the `verifyImages` rule into two entries — one for signature verification and one for SLSA-provenance attestation verification — since a single Kyverno entry can only verify one or the other.
