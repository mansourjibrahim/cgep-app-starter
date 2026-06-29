# Capstone Write-Up — Acme Health Patient Intake System

**Author:** Mansour Jamal Ibrahim
**Primary framework:** HIPAA Security Rule (45 CFR Part 164, Subpart C)
**Repository:** https://github.com/mansourjibrahim/cgep-app-starter
**Date:** June 2026

---

## 1. Framework selection and rationale

This system was assessed against the **HIPAA Security Rule** as its primary
compliance framework. The selection is driven by the nature of the workload:
the Patient Intake API ingests and stores protected health information (PHI),
and every resource in the starter is tagged `DataClass = phi`. For a covered
entity or business associate handling PHI, the HIPAA Security Rule is the
controlling federal standard, and an assessor reviewing this system would
expect it to be the governing framework.

HIPAA was selected over the two alternatives for three reasons:

1. **Defensibility.** A telehealth workload handling PHI measured against any
   framework other than HIPAA would invite the immediate question of why the
   sector-specific privacy rule was not chosen. HIPAA is the least contestable
   choice for this system.
2. **Control-to-gap traceability.** Each technical gap in the starter maps
   cleanly to a specific HIPAA Technical or Administrative Safeguard (for
   example, encryption at rest to 164.312(a)(2)(iv), transmission security to
   164.312(e)(1)). This produces an unambiguous control mapping.
3. **Intelligibility of the control objective.** HIPAA's safeguards express
   plain protection objectives ("is the patient data encrypted, recoverable,
   and access-controlled?"), which keeps the policy and OSCAL layers grounded
   in a clear intent rather than an abstract criteria set.

SOC 2 (Trust Services Criteria) and CMMC Level 2 were both considered and remain
defensible secondary mappings; relevant SOC 2 and CMMC control identifiers for
each gap are retained in the project's gap analysis for future cross-mapping.

### Catalog note

There is no official NIST OSCAL catalog for the HIPAA Security Rule. Following
common practice, this project cites **NIST SP 800-66 Rev. 2** (*Implementing the
HIPAA Security Rule*) as the catalog `source` in the OSCAL component definition,
and references the underlying 45 CFR 164.x sections as properties on each
implemented requirement.

---

## 2. Scope and gap remediation

The starter ships with eight named, intentional compliance gaps. Consistent with
the program guidance to prioritise depth over breadth, **five gaps were selected
for full technical remediation** across the Terraform, policy, and OSCAL layers.
The remaining three were consciously deferred and are documented in Section 6.

### Gaps remediated

| Gap | HIPAA control | Remediation | Enforcing resource |
|-----|---------------|-------------|--------------------|
| GAP-01 | 164.312(a)(2)(iv) | S3 uploads bucket encrypted at rest with a customer-managed KMS key (CMK) instead of the AWS-managed default | `aws_s3_bucket_server_side_encryption_configuration.uploads` |
| GAP-02 | 164.312(a)(2)(iv) | DynamoDB submissions table encrypted with the same CMK | `aws_dynamodb_table.intake` (inline `server_side_encryption`) |
| GAP-03 | 164.312(e)(1) | Bucket policy denies any request where `aws:SecureTransport` is false, enforcing TLS in transit | `aws_s3_bucket_policy.uploads_tls` |
| GAP-04 | 164.308(a)(7) | Versioning enabled on the PHI bucket for recoverability of overwritten or deleted objects | `aws_s3_bucket_versioning.uploads` |
| GAP-07 | 164.312(a)(1) | Lambda execution role scoped from `dynamodb:*` / `s3:*` wildcards to `dynamodb:PutItem`, `s3:PutObject`, and the minimal KMS actions required for encrypted writes | `aws_iam_role_policy.lambda_inline` |

Each remediation is applied additively in `terraform/grc_baseline.tf` and wired
to the starter's resources by direct reference. The starter's own resources
remain present and unmodified except where AWS requires inline configuration
(DynamoDB encryption and the IAM policy), in keeping with a "govern, do not
rewrite" approach.

---

## 3. Architecture of the control system

The governance system is organised in four layers wrapped around the unmodified
workload.

**Layer 1 — Terraform GRC baseline.** Adds a customer-managed KMS key with
rotation enabled, brings the S3 uploads bucket and DynamoDB table under that key,
enforces TLS-only transport and versioning, scopes the Lambda IAM role to least
privilege, and provisions an immutable evidence vault (S3 with Object Lock).
A GitHub Actions OIDC identity provider and a scoped CI role are also defined
here so the pipeline can authenticate without long-lived credentials.

**Layer 2 — OPA/Rego policy suite.** Five policies under
`policies/`, each carrying a metadata block naming the framework, control
ID(s), and severity, and each catching a specific gap from the gap analysis.
Every policy has a companion `_test.rego` with a passing and a failing fixture;
`opa test ./policies` reports 10/10 passing.

**Layer 3 — CI policy gate.** A GitHub Actions workflow
(`.github/workflows/grc-gate.yml`) authenticates to AWS via OIDC, runs
`terraform plan`, exports the plan to JSON, and evaluates the full policy suite
against it through `scripts/policy-gate.sh`. The gate fails closed: any policy
violation produces a non-zero exit and blocks the pull request.

**Layer 4 — OSCAL component definition.**
`oscal/components/acme-intake-component.json` describes the governed system as a
single component implementing five HIPAA controls, each requirement pointing at
the real Terraform resource and AWS ARN that satisfies it, with the catalog
`source` set to NIST SP 800-66 Rev. 2. The file validates with `trestle`.

---

## 4. Key design decisions and trade-offs

**Customer-managed key over AWS-managed default.** AWS now enables SSE-S3
encryption on new buckets by default. The baseline nonetheless provisions an
explicit customer-managed CMK, because under HIPAA the covered entity must be
able to attest to *custody* of the encryption key, not merely to the presence of
encryption. An organisation cannot attest to a default it did not configure.

**Least privilege scoped to observed behaviour.** The Lambda IAM role was
reduced to the exact actions the handler invokes (`PutItem`, `PutObject`) plus
the minimal KMS actions required for encrypted writes. During verification the
role initially failed at runtime with a `kms:Decrypt` denial: AWS's
envelope-encryption flow requires `Decrypt` even on a write path. The role was
adjusted to include `Decrypt` while still excluding all read actions
(`GetItem`, `Scan`, `GetObject`), so the function can write encrypted PHI but
cannot read PHI back. This illustrates that "least privilege" means the least
privilege that still functions, which can only be established by testing.

**Object Lock in GOVERNANCE mode.** The evidence vault uses S3 Object Lock in
GOVERNANCE mode with a one-day default retention, rather than COMPLIANCE mode.
GOVERNANCE provides immutability while allowing a sufficiently privileged
principal to remove objects, which is appropriate for a time-boxed lab
environment that must be cleanly decommissioned. For a production PHI evidence
store, COMPLIANCE mode with a retention period matched to the applicable record
retention requirement would be the defensible choice; the mode is a deliberate,
documented trade-off.

**OIDC federation over stored credentials.** The pipeline authenticates to AWS
using GitHub's OIDC provider and a role whose trust policy is restricted to this
specific repository, rather than storing long-lived AWS access keys as
repository secrets. No standing credential exists to be leaked; the pipeline
receives short-lived, scoped credentials at run time.

**Manual approval before apply.** The design gates any apply step behind manual
approval rather than applying automatically on merge, reducing the risk of an
automated mutation to a live PHI system. This is permitted by the program brief
and is the more conservative posture for a healthcare workload.

---

## 5. Verification and a noted policy-evaluation defect

The policy gate was validated against both a compliant plan (which passes) and a
deliberately non-compliant plan that reintroduces GAP-01 (which is blocked). Two
pull requests in the repository history demonstrate this: one that passes the
gate, and one that is blocked by it.

During this verification, a significant defect was discovered and corrected in
the policy layer, documented here in full because it materially affects the
reliability of any policy-as-code gate:

1. **State-dependent input path.** The policies initially read resource state
   from the plan's `planned_values` block. This block is populated differently
   depending on whether Terraform state is present. In CI, where no state exists,
   the policies evaluated a different data shape than they did locally, and did
   not fire. The policies were refactored to read `resource_changes[].change.after`,
   which is populated deterministically regardless of state.

2. **Silent failure on unknown values.** A deny rule constructed its violation
   message from `after.bucket`. For a resource that does not yet exist, Terraform
   omits attributes whose values are not yet known, so `after.bucket` was absent.
   The reference to a missing field caused the rule body to fail evaluation,
   which produced **no** violation — meaning a non-compliant plan passed the gate.
   A policy that errors during message construction is indistinguishable, at the
   gate, from a policy that finds no violation. The rules were rewritten to derive
   identifiers from the always-present `resource_changes[].address` field.

3. **Tool input-shape mismatch.** `conftest` and `opa eval` present the plan
   document to policies differently. The gate was reimplemented as a small script
   invoking `opa eval` directly, which evaluates the full plan as a single input
   and produces an explicit non-zero exit on any violation.

The general lesson recorded for future work: **a policy gate must be validated
against a known-bad input, not only a known-good one.** A gate that has only ever
been observed to pass has not been shown to work.

---

## 6. Known gaps and next-sprint roadmap

The following items are intentionally incomplete and are recorded honestly rather
than represented as finished.

**Deferred starter gaps.** Three of the eight starter gaps were not remediated in
this iteration and would be the first priority of a subsequent sprint:

- **GAP-05 — Lambda not deployed into the VPC.** The function runs in the default
  Lambda network environment rather than the private subnets the starter
  provisions. Remediation: add a `vpc_config` block referencing the existing
  private subnets and a dedicated security group (164.312(e)(1), boundary
  protection).
- **GAP-06 — No reserved concurrency, dead-letter queue, or tracing on the
  Lambda.** Remediation: configure reserved concurrency, a DLQ, and X-Ray
  tracing (system monitoring).
- **GAP-08 — No API Gateway access logging, throttling, or WAF.** Remediation:
  enable stage access logging, configure throttling, and associate a WAF web ACL
  (164.312(b), audit controls).

**Pipeline completion.** The CI pipeline currently implements plan and policy-gate
stages and is proven to fail closed. The apply, evidence-signing (Cosign keyless
via OIDC), and signed-bundle upload stages are designed (the immutable evidence
vault and the scoped CI write permissions to it already exist) but are not yet
implemented. As a result, no signed evidence bundle has yet been written to the
vault. Completing these stages is required to demonstrate full chain of custody
and is the second priority for the next sprint.

**Remote state backend.** Terraform state is currently local. Migrating to an S3
backend with state locking would allow the CI pipeline to evaluate plans against
real state rather than planning from empty, and is a prerequisite for a fully
automated apply stage.

---

## 7. Summary

This submission delivers a HIPAA-aligned governance system wrapped around an
unmodified PHI workload: a Terraform baseline closing five mapped gaps, a
five-policy OPA suite with passing tests, a CI policy gate proven to fail closed
against a known-bad change, and a trestle-validated OSCAL component tracing each
control to a real enforcing resource. The signing and evidence-upload stages of
the pipeline, and three lower-severity starter gaps, are documented as known,
deferred work rather than represented as complete.
