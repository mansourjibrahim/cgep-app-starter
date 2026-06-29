package compliance.hipaa.least_privilege
import rego.v1

test_scoped_passes if {
    count(deny) == 0 with input as {"resource_changes": [{
        "type": "aws_iam_role_policy",
        "change": {"after": {"name": "good", "policy": "{\"Action\":[\"dynamodb:PutItem\",\"s3:PutObject\"]}"}},
    }]}
}
test_wildcard_fails if {
    c := count(deny) with input as {"resource_changes": [{
        "type": "aws_iam_role_policy",
        "change": {"after": {"name": "bad", "policy": "{\"Action\":\"dynamodb:*\"}"}},
    }]}
    c > 0
}
