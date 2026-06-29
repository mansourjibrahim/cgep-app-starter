# METADATA
# title: Lambda IAM policy must not use service-level wildcards
# description: GAP-07 — inline policy must not grant dynamodb:* or s3:* wildcards.
# custom:
#   framework: hipaa
#   controls: ["164.312(a)(1)"]
#   severity: high
package compliance.hipaa.least_privilege

import rego.v1

forbidden_wildcards := ["dynamodb:*", "s3:*", "iam:*", "kms:*"]

deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_iam_role_policy"
    some wildcard in forbidden_wildcards
    contains(rc.change.after.policy, wildcard)
    msg := sprintf(
        "GAP-07 [HIPAA 164.312(a)(1)]: %s grants over-broad action '%s' (least-privilege violation)",
        [rc.address, wildcard],
    )
}
