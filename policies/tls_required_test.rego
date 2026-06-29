package compliance.hipaa.tls_required
import rego.v1

test_tls_passes if {
    count(deny) == 0 with input as {"resource_changes": [{
        "address": "aws_s3_bucket_policy.good",
        "type": "aws_s3_bucket_policy",
        "change": {"after": {"policy": "{\"aws:SecureTransport\":\"false\"}"}},
    }]}
}
test_no_tls_fails if {
    count(deny) == 1 with input as {"resource_changes": [{
        "address": "aws_s3_bucket_policy.bad",
        "type": "aws_s3_bucket_policy",
        "change": {"after": {"policy": "{\"Action\":\"s3:GetObject\"}"}},
    }]}
}
