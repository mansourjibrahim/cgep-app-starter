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
    some rc in input.resource_changes
    rc.type == "aws_dynamodb_table"
    not table_has_cmk(rc.change.after)
    msg := sprintf(
        "GAP-02 [HIPAA 164.312(a)(2)(iv)]: %s is not encrypted with a customer-managed CMK",
        [rc.address],
    )
}

table_has_cmk(after) if {
    after.server_side_encryption[0].enabled == true
}
