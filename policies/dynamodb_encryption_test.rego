package compliance.hipaa.dynamodb_encryption
import rego.v1

test_cmk_passes if {
    count(deny) == 0 with input as {"resource_changes": [{
        "address": "aws_dynamodb_table.good",
        "type": "aws_dynamodb_table",
        "change": {"after": {"server_side_encryption": [{"enabled": true}]}},
    }]}
}
test_default_fails if {
    count(deny) == 1 with input as {"resource_changes": [{
        "address": "aws_dynamodb_table.bad",
        "type": "aws_dynamodb_table",
        "change": {"after": {"server_side_encryption": []}},
    }]}
}
