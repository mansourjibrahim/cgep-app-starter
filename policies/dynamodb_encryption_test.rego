package compliance.hipaa.dynamodb_encryption
import rego.v1

test_cmk_table_passes if {
    count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [{
        "type": "aws_dynamodb_table",
        "values": {"name": "good", "server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:::key/x"}]},
    }]}}}
}

test_default_key_table_fails if {
    count(deny) == 1 with input as {"planned_values": {"root_module": {"resources": [{
        "type": "aws_dynamodb_table",
        "values": {"name": "bad", "server_side_encryption": []},
    }]}}}
}
