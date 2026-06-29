package compliance.hipaa.versioning
import rego.v1

test_versioning_enabled_passes if {
    count(deny) == 0 with input as {"planned_values": {"root_module": {"resources": [{
        "type": "aws_s3_bucket_versioning",
        "values": {"bucket": "good", "versioning_configuration": [{"status": "Enabled"}]},
    }]}}}
}

test_versioning_disabled_fails if {
    count(deny) == 1 with input as {"planned_values": {"root_module": {"resources": [{
        "type": "aws_s3_bucket_versioning",
        "values": {"bucket": "bad", "versioning_configuration": [{"status": "Suspended"}]},
    }]}}}
}
