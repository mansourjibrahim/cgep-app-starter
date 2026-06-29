# METADATA
# title: PHI S3 buckets must use customer-managed KMS encryption
# description: GAP-01 — uploads bucket must use aws:kms with a CMK, not SSE-S3.
# custom:
#   framework: hipaa
#   controls: ["164.312(a)(2)(iv)", "164.308(a)(7)"]
#   severity: high
package compliance.hipaa.encryption

import rego.v1

deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_s3_bucket_server_side_encryption_configuration"
    algorithm := rc.change.after.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm
    algorithm != "aws:kms"
    msg := sprintf(
        "GAP-01 [HIPAA 164.312(a)(2)(iv)]: %s uses '%s', must use 'aws:kms' (customer-managed CMK)",
        [rc.address, algorithm],
    )
}
