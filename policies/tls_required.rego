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
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_s3_bucket_policy"
    not policy_denies_insecure_transport(resource)
    msg := sprintf(
        "GAP-03 [HIPAA 164.312(e)(1)]: bucket policy on '%s' does not deny non-TLS (aws:SecureTransport) requests",
        [resource.values.bucket],
    )
}

policy_denies_insecure_transport(resource) if {
    contains(resource.values.policy, "aws:SecureTransport")
}
