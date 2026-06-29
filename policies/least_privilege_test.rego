package compliance.hipaa.least_privilege
import rego.v1

test_scoped_policy_passes if {
    count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [{
        "type": "aws_iam_role_policy",
        "values": {"name": "good", "policy": "{\"Action\":[\"dynamodb:PutItem\",\"s3:PutObject\"]}"},
    }]}}}
}

test_wildcard_policy_fails if {
    deny_count := count(deny) with input as {"planned_values": {"root_module": {"resources": [{
        "type": "aws_iam_role_policy",
        "values": {"name": "bad", "policy": "{\"Action\":\"dynamodb:*\"}"},
    }]}}}
    deny_count > 0
}
