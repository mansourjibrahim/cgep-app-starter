package compliance.hipaa.versioning
import rego.v1

test_enabled_passes if {
    count(deny) == 0 with input as {"resource_changes": [{
        "type": "aws_s3_bucket_versioning",
        "change": {"after": {"bucket": "good", "versioning_configuration": [{"status": "Enabled"}]}},
    }]}
}
test_suspended_fails if {
    count(deny) == 1 with input as {"resource_changes": [{
        "type": "aws_s3_bucket_versioning",
        "change": {"after": {"bucket": "bad", "versioning_configuration": [{"status": "Suspended"}]}},
    }]}
}
