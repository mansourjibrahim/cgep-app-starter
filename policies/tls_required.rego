# METADATA
# title: PHI S3 buckets must deny non-TLS requests
# description: GAP-03 — uploads bucket policy must deny aws:SecureTransport=false.
# custom:
#   framework: hipaa
#   controls: ["164.312(e)(1)"]
#   severity: high
package compliance.hipaa.tls_required

import rego.v1

deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_s3_bucket_policy"
    not contains(rc.change.after.policy, "aws:SecureTransport")
    msg := sprintf(
        "GAP-03 [HIPAA 164.312(e)(1)]: bucket policy on '%s' does not deny non-TLS (aws:SecureTransport) requests",
        [rc.change.after.bucket],
    )
}
