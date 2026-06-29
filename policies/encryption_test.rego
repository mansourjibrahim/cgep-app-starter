package compliance.hipaa.encryption
import rego.v1

test_kms_passes if {
    count(deny) == 0 with input as {"resource_changes": [{
        "address": "aws_s3_bucket_server_side_encryption_configuration.good",
        "type": "aws_s3_bucket_server_side_encryption_configuration",
        "change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}},
    }]}
}
test_aes256_fails if {
    count(deny) == 1 with input as {"resource_changes": [{
        "address": "aws_s3_bucket_server_side_encryption_configuration.bad",
        "type": "aws_s3_bucket_server_side_encryption_configuration",
        "change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]}},
    }]}
}
