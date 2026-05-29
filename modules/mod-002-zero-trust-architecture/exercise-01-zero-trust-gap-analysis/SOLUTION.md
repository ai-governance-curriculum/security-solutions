# SOLUTION — Exercise 01: Zero-Trust Gap Analysis

> Read this *after* attempting the exercise. The point is to discover
> what you miss before being told what to spot.

## 1. Solution overview

The exercise asks for a gap analysis of the SmartRecs system against
the five zero-trust tenets compressed in module 02 lecture-notes §1.1.
NIST SP 800-207 §2.1 itself lists **seven** tenets; the lecture
compresses them to five for pedagogical clarity. The five lecture
tenets are a faithful summary, but a learner who wants to cite NIST
verbatim in a real review should use the seven-tenet phrasing from
the publication.

A correct answer for SmartRecs has three properties:

1. **Per-tenet granularity.** Each tenet gets its own assessment;
   a single "we have some auth" verdict misses the point of the
   framework.
2. **Concrete gaps named to specific workloads.** "Improve
   authentication" is not a gap. "Training job, serving pod,
   gateway, governance pod, and notebook all share an API-key
   credential class that is not bound to workload identity" is a
   gap.
3. **Honest about residual threat.** Zero-trust does not address
   evasion, model extraction, poisoning, or compliance reporting.
   The analysis should call this out (it is also worth a section
   in the Exercise 05 roadmap).

This solution walks the five tenets, identifies SmartRecs' actual
posture from the Module 01 system description, and proposes
specific architectural changes scored by effort × impact.

## 2. Implementation (worked answer)

The remainder of this section is the worked artifact a learner
should produce. Treat it as a fully written reference deliverable,
not as commentary.

---

### Zero-Trust Gap Analysis: SmartRecs

**Author:** *reference solution*
**Date:** 2026-05
**System under analysis:** SmartRecs recommendation platform as
described in
[`mod-001 exercise-01`](https://github.com/ai-infra-curriculum/ai-infra-security-learning/blob/main/lessons/mod-001-ml-security-foundations/exercises/exercise-01-threat-model-a-small-ml-system.md).

**Reference framework:** NIST SP 800-207 *Zero Trust Architecture*
(https://csrc.nist.gov/pubs/sp/800/207/final), compressed to the
five lecture tenets in module 02 §1.1.

#### Tenet 1 — Every resource access is authenticated, authorized, and encrypted, regardless of origin

- **Statement.** Network position confers no privilege. Every
  workload-to-workload and user-to-workload call carries an
  identity, an authorization decision against that identity, and
  cryptographic protection in transit.
- **Assessment:** Non-compliant.
- **Evidence in SmartRecs.**
  - Customers authenticate to the public API with a per-store API
    key (the only authenticated boundary).
  - Internal calls (gateway → serving, serving → artifact store,
    training → warehouse, training → S3 artifact path) rely on
    cluster network position and shared IAM roles. There is no
    workload-identity authentication on the east-west path.
  - The audit log to S3 is keyed on customer-store, not on the
    issuing workload identity.
- **Required architectural change.**
  Introduce SPIFFE-style workload identity for the four workload
  classes (training, serving, gateway, governance — notebook
  comes in tenet 3). Issue SVIDs from SPIRE or, on managed
  Kubernetes, use IRSA / GKE Workload Identity / AAD Workload
  Identity to bind a cloud identity to each `ServiceAccount`.
  Turn on `PeerAuthentication: STRICT` mesh-wide so that
  in-cluster calls fail closed when an SVID is missing.
- **Effort × Impact:** Effort **large** (8–12 eng-weeks to wire
  SPIRE/IRSA + sidecar mesh + audit log key change). Impact
  **high** (closes the largest perimeter assumption).

#### Tenet 2 — Access decisions are made per-request, not per-session

- **Statement.** Tokens issued at session start are not standing
  authorization. Token lifetime is short and reauthentication is
  frequent enough that posture changes can revoke access in
  near-real-time.
- **Assessment:** Non-compliant.
- **Evidence in SmartRecs.**
  - Customer API keys are long-lived (no documented rotation).
  - The serving pod pulls the model artifact at startup; whatever
    AWS credentials it has at startup live for the pod's lifetime.
  - Training jobs use the same warehouse credential nightly.
- **Required architectural change.**
  - Replace static API keys with short-lived OIDC access tokens
    (issued by SmartRecs' identity provider; ~1h TTL with
    refresh).
  - Replace static workload credentials with rotating SVIDs (~1h
    TTL) from SPIRE, or with IRSA's automatic STS token rotation.
  - Adopt Vault dynamic secrets for the training-warehouse
    credentials so the credential is per-job, not per-team.
- **Effort × Impact:** Effort **medium** (4–6 eng-weeks once
  tenet 1 lands). Impact **high** (revocation actually works;
  leaked credentials decay).

#### Tenet 3 — Resource access follows least privilege, scoped to the specific operation

- **Statement.** Each identity gets the narrowest scope it needs
  to do the job in front of it — not a class-wide role, not a
  team-wide role.
- **Assessment:** Non-compliant.
- **Evidence in SmartRecs.**
  - All training jobs apparently share one warehouse credential
    and one S3 write path.
  - Serving pods can presumably read every model artifact in the
    bucket, not only the `recs-prod`-pointed version.
  - The implied "notebook / experimentation" environment, if
    present, has broad read access (the standard pattern for
    teams of this size — and the lecture explicitly flags this
    as the hardest scope to constrain).
- **Required architectural change.**
  - Scope serving identity to `s3://models/v<N>/...` where N is
    the version it was promoted to serve; deny all other model
    versions.
  - Scope training identity to a per-run prefix
    (`s3://models/recs-v<N>/run-<id>/`) and to a per-run
    warehouse credential issued by Vault.
  - Isolate notebook environments into their own namespace
    with no production-data IAM and a time-bounded SVID
    (expires end of working day, per lecture-notes §8.4).
- **Effort × Impact:** Effort **medium** (3–5 eng-weeks of IAM
  policy work). Impact **high** (reduces blast radius from "team
  compromise" to "single job compromise").

#### Tenet 4 — All assets are inventoried, identifiable, and protected

- **Statement.** Every asset (workload, dataset, model artifact,
  credential, endpoint) has a unique identifier, an owner, and an
  observable posture.
- **Assessment:** Partially compliant.
- **Evidence in SmartRecs.**
  - Model artifacts have version tags (`recs-vN`), so they are
    inventoried at the artifact level.
  - Per-pod Prometheus metrics exist (workloads are observable).
  - There is no documented inventory of credentials, no asset
    register, and no per-pod posture signal beyond liveness.
  - The audit log retention is 30 days — useful for incident
    investigation, insufficient for posture history.
- **Required architectural change.**
  - Maintain a credential / secret inventory in Vault (Module 05).
  - Add workload posture signals: Pod Security Standards
    `restricted` profile (Kubernetes docs:
    https://kubernetes.io/docs/concepts/security/pod-security-standards/),
    image-digest pinning, admission policies that record the
    bound identity at admission time.
  - Extend audit retention to at least 1 year for the per-request
    log; this is also the typical compliance floor (covered in
    Module 07).
- **Effort × Impact:** Effort **small to medium** (2–4 eng-weeks).
  Impact **medium** (enables the other tenets to be measured).

#### Tenet 5 — Posture informs access; failing assets lose privileges, not just generate alerts

- **Statement.** Continuous evaluation of an asset's security
  state feeds the authorization decision. A pod that failed an
  admission policy, an image that just got a critical CVE, or a
  workload running with elevated privileges should be denied or
  downgraded — not merely logged.
- **Assessment:** Non-compliant.
- **Evidence in SmartRecs.**
  - No runtime security (no Falco, no Tetragon, no equivalent).
  - No image-scan gate on admission.
  - Promotion to `recs-prod` is a manual ticket — the posture of
    the promoted artifact is not re-evaluated programmatically.
- **Required architectural change.**
  - Admission control with Kyverno or Gatekeeper (Module 09)
    rejecting unsigned or vulnerable images.
  - Runtime detection (Falco; cross-reference
    [project-1-zero-trust/falco-rules/ml-platform.yaml](../../../projects/project-1-zero-trust/falco-rules/ml-platform.yaml))
    that flags privileged containers and unexpected egress.
  - Wire detections back to the AuthorizationPolicy: a failed
    posture signal should result in a temporary deny entry in
    the mesh until the workload is replaced. This is the hardest
    of the five to implement well and is realistically a Phase 3
    item in the Exercise 05 roadmap.
- **Effort × Impact:** Effort **large** (8–12 eng-weeks once
  policy-as-code and runtime security are operational). Impact
  **medium** (most damage is already prevented by tenets 1–3;
  this is the last-mile catch).

#### Summary table

| Tenet | Verdict | Top fix | Effort | Impact |
|---|---|---|---|---|
| 1 | Non-compliant | SPIFFE/IRSA workload identity + mesh STRICT | L | H |
| 2 | Non-compliant | Short-lived SVIDs and OIDC tokens; Vault dynamic creds | M | H |
| 3 | Non-compliant | Per-version model IAM; per-run warehouse creds; notebook isolation | M | H |
| 4 | Partial | Asset/credential inventory; PSS `restricted`; longer audit retention | S–M | M |
| 5 | Non-compliant | Admission policy + runtime detection feeding mesh deny | L | M |

#### Top 3 gaps to address first

1. **Workload identity foundation (Tenet 1).** Without it, the
   gaps in tenets 2, 3, and 5 cannot be closed — every other
   fix assumes the requester can be identified. The fact that
   internal SmartRecs traffic is unauthenticated is also the
   single condition most likely to turn a contained incident
   into a platform-wide breach.
2. **Per-version model IAM and per-run training credentials
   (Tenet 3).** This caps the blast radius of a compromise in
   the most likely class of incident: a training job or
   serving pod with bad code paths.
3. **Asset and credential inventory (Tenet 4).** This is the
   cheapest of the three, blocks no other work, and is the
   prerequisite for any meaningful audit later in the
   compliance module.

The classic alternative — "install Istio first because the demo
looks impressive" — is rejected here because Istio's mesh is
useful only once workloads have identities. Mesh without identity
is encrypted traffic between unknown parties.

#### What zero-trust doesn't help with at SmartRecs

The following threats from the Module 01 STRIDE+ML model survive
even full zero-trust adoption. Each one belongs to a later module
in the track.

- **Model extraction via the paid API.** The attacker has a
  valid API key, valid OIDC token, and valid query budget. Mesh
  identity is by-design satisfied. Mitigations: query-pattern
  detection and rate budgets (Modules 06 and 11).
- **Adversarial inputs (ML01 evasion).** Authenticated calls
  passing crafted inputs. Mitigations: adversarial training and
  input validation (Module 06).
- **Training-data poisoning via the feedback loop.** Click /
  purchase events arrive through the same channel as legitimate
  feedback. Mitigations: data provenance and ingest filtering
  (Modules 07 and 10).
- **Compliance evidence.** Zero-trust improves controls; it does
  not produce SOC 2 / ISO 27001 / GDPR evidence on its own.
  Compliance reporting is its own workstream (Module 07).
- **Insider with legitimate access.** Zero-trust assumes the
  identity is correctly issued. A staff member with a valid
  identity who decides to exfiltrate is constrained by the
  least-privilege scope (so the lecture's per-version IAM
  matters) but not stopped.

---

## 3. Validation steps

The artifact is a written gap analysis, not running code; the
validation is a self-check the learner runs against their
document.

1. **Open the artifact.** Confirm five tenets are addressed in
   five separate sections, each with the four required parts:
   statement, assessment, evidence, required change, and
   effort × impact.
2. **Open the Module 01 threat model.** For every gap claimed,
   cite which SmartRecs workload or asset is affected. If a
   gap names no workload, the gap is too vague.
3. **Cross-check tenet 5.** A common failure mode is to claim
   "we'll add Falco and we're done." Verify the proposed
   change closes the loop — posture signal feeds the
   authorization decision, not just an alert dashboard.
4. **Open the residual-threat section.** Confirm at least three
   threats from the Module 01 STRIDE+ML table appear here.
   Calibration without acknowledged residuals is overclaiming.
5. **Prioritization sanity-check.** The top 3 should be a
   strict subset of the table; the order should be defensible
   in one sentence each. If the order is "the most exciting"
   rather than "what unblocks the rest," that is the bug.

## 4. Rubric / review checklist

Score 1 point per row that is fully present. 8/10 or above is a
passing analysis.

| # | Criterion | Pass condition |
|---|---|---|
| 1 | Tenet 1 addressed | Statement, verdict, named SmartRecs evidence, concrete fix |
| 2 | Tenet 2 addressed | As above |
| 3 | Tenet 3 addressed | As above |
| 4 | Tenet 4 addressed | As above |
| 5 | Tenet 5 addressed | As above; closure (posture → access) not just alerting |
| 6 | Workloads named | Every gap references a specific workload class (training, serving, gateway, governance, notebook) |
| 7 | Effort × impact scored | Each gap is rated S/M/L and H/M/L with one-line justification |
| 8 | Top 3 prioritization defensible | Selection unblocks downstream work; not popularity-ranked |
| 9 | Residual-threat section | At least 3 Module 01 threats acknowledged as unaddressed by zero-trust |
| 10 | Style | 2–3 pages, table format used for summary, citations to NIST SP 800-207 |

A common borderline case: the learner names good fixes but
leaves them unscored. Push back on that — unscored fixes are
useless to a roadmap.

## 5. Common mistakes

- **Treating zero-trust as a single yes/no verdict.** The
  exercise is per-tenet on purpose.
- **Citing controls SmartRecs doesn't have.** "We have SOC 2"
  is not a tenet 4 mitigation; SOC 2 is a compliance regime,
  not an asset inventory.
- **Recommending Istio first.** Without identity, Istio is
  encrypted traffic between unknown parties (lecture-notes
  §1.2 misconception table). Tenet 1 must precede mesh
  deployment, not follow it.
- **Effort estimates of days.** A genuinely useful effort
  estimate is in eng-weeks at minimum. Days is roadmap
  fiction.
- **Tenet 5 confused with monitoring.** Posture-informs-access
  is not "we send Falco alerts to Slack." It is
  "Falco-detected misconfig revokes the workload's SVID until
  it is replaced."
- **No residual-threat section.** Overclaim. Each instance
  where the analysis claims zero-trust solves a problem it
  doesn't (poisoning, evasion, model extraction, insider) is
  a calibration failure.
- **Quoting NIST verbatim.** The exercise asks for the
  learner's own phrasing per tenet. Verbatim quotes do not
  demonstrate understanding.

## 6. References

- **NIST SP 800-207 — Zero Trust Architecture.**
  https://csrc.nist.gov/pubs/sp/800/207/final
  Sections 2.1 (tenets), 2.2 (logical components), 3.1
  (variations) are the most useful for this exercise.
- **Module 02 lecture notes §1.1** (five-tenet compression
  for pedagogy) and §1.2 (common misconceptions about
  zero-trust).
- **Module 01 exercise 01** — SmartRecs system description
  and threat model.
  [`lessons/mod-001-ml-security-foundations/exercises/exercise-01-threat-model-a-small-ml-system.md`](https://github.com/ai-infra-curriculum/ai-infra-security-learning/blob/main/lessons/mod-001-ml-security-foundations/exercises/exercise-01-threat-model-a-small-ml-system.md)
- **MITRE ATLAS.** https://atlas.mitre.org/
  Useful when mapping the residual-threat list to named
  tactics (e.g., model extraction → AML.T0044).
- **Kubernetes Pod Security Standards.**
  https://kubernetes.io/docs/concepts/security/pod-security-standards/
  Cited under tenet 4 as a posture baseline.
- **Cross-reference:** [`projects/project-1-zero-trust/SOLUTION.md`](../../../projects/project-1-zero-trust/SOLUTION.md)
  shows what the after-state of these gaps looks like in code.
