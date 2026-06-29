package compliance.hipaa.least_privilege
import rego.v1

test_scoped_passes if {
    count(deny) == 0 with input as {"resource_changes": [{
        "address": "aws_iam_role_policy.good",
        "type": "aws_iam_role_policy",
        "change": {"after": {"policy": "{\"Action\":[\"dynamodb:PutItem\",\"s3:PutObject\"]}"}},
    }]}
}
test_wildcard_fails if {
    c := count(deny) with input as {"resource_changes": [{
        "address": "aws_iam_role_policy.bad",
        "type": "aws_iam_role_policy",
        "change": {"after": {"policy": "{\"Action\":\"dynamodb:*\"}"}},
    }]}
    c > 0
}
