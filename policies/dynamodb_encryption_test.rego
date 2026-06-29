package compliance.hipaa.dynamodb_encryption
import rego.v1

test_cmk_passes if {
    count(deny) == 0 with input as {"resource_changes": [{
        "type": "aws_dynamodb_table",
        "change": {"after": {"name": "good", "server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:::key/x"}]}},
    }]}
}
test_default_fails if {
    count(deny) == 1 with input as {"resource_changes": [{
        "type": "aws_dynamodb_table",
        "change": {"after": {"name": "bad", "server_side_encryption": []}},
    }]}
}
