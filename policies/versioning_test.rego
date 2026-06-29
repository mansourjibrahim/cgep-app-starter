package compliance.hipaa.versioning
import rego.v1

test_enabled_passes if {
    count(deny) == 0 with input as {"resource_changes": [{
        "address": "aws_s3_bucket_versioning.good",
        "type": "aws_s3_bucket_versioning",
        "change": {"after": {"versioning_configuration": [{"status": "Enabled"}]}},
    }]}
}
test_suspended_fails if {
    count(deny) == 1 with input as {"resource_changes": [{
        "address": "aws_s3_bucket_versioning.bad",
        "type": "aws_s3_bucket_versioning",
        "change": {"after": {"versioning_configuration": [{"status": "Suspended"}]}},
    }]}
}
