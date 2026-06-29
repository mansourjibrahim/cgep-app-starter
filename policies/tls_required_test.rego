package compliance.hipaa.tls_required
import rego.v1

test_tls_policy_passes if {
    count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [{
        "type": "aws_s3_bucket_policy",
        "values": {"bucket": "good", "policy": "{\"aws:SecureTransport\":\"false\"}"},
    }]}}}
}

test_no_tls_policy_fails if {
    count(deny) == 1 with input as {"planned_values": {"root_module": {"resources": [{
        "type": "aws_s3_bucket_policy",
        "values": {"bucket": "bad", "policy": "{\"Action\":\"s3:GetObject\"}"},
    }]}}}
}
