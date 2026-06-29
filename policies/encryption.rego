# METADATA
# title: PHI S3 buckets must use customer-managed KMS encryption
# description: GAP-01 — uploads bucket must use aws:kms with a CMK, not SSE-S3.
# custom:
#   framework: hipaa
#   controls: ["164.312(a)(2)(iv)", "164.308(a)(7)"]
#   severity: high
package compliance.hipaa.encryption

import rego.v1

# Walk the plan and collect every S3 encryption-config resource.
enc_configs contains resource if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
}

# DENY if any encryption config is not using aws:kms.
deny contains msg if {
    some resource in enc_configs
    algorithm := resource.values.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm
    algorithm != "aws:kms"
    msg := sprintf(
        "GAP-01 [HIPAA 164.312(a)(2)(iv)]: bucket '%s' uses '%s', must use 'aws:kms' (customer-managed CMK)",
        [resource.values.bucket, algorithm],
    )
}
