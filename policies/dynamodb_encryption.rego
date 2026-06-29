# METADATA
# title: PHI DynamoDB tables must use customer-managed KMS encryption
# description: GAP-02 — intake table must set server_side_encryption with a CMK.
# custom:
#   framework: hipaa
#   controls: ["164.312(a)(2)(iv)"]
#   severity: high
package compliance.hipaa.dynamodb_encryption

import rego.v1

deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_dynamodb_table"
    not table_has_cmk(resource)
    msg := sprintf(
        "GAP-02 [HIPAA 164.312(a)(2)(iv)]: DynamoDB table '%s' is not encrypted with a customer-managed CMK",
        [resource.values.name],
    )
}

table_has_cmk(resource) if {
    sse := resource.values.server_side_encryption[0]
    sse.enabled == true
    sse.kms_key_arn != ""
}
