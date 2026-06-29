package compliance.hipaa.encryption

import rego.v1

# A compliant encryption config (aws:kms) — deny must be EMPTY.
test_kms_encryption_passes if {
    count(deny) == 0 with input as {
        "planned_values": {"root_module": {"resources": [{
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "values": {
                "bucket": "good-bucket",
                "rule": [{"apply_server_side_encryption_by_default": [{
                    "sse_algorithm": "aws:kms"
                }]}],
            },
        }]}}
    }
}

# A non-compliant config (AES256) — deny must contain EXACTLY ONE message.
test_aes256_encryption_fails if {
    count(deny) == 1 with input as {
        "planned_values": {"root_module": {"resources": [{
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "values": {
                "bucket": "bad-bucket",
                "rule": [{"apply_server_side_encryption_by_default": [{
                    "sse_algorithm": "AES256"
                }]}],
            },
        }]}}
    }
}
