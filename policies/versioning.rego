# METADATA
# title: PHI S3 buckets must have versioning enabled
# description: GAP-04 — uploads bucket must have versioning Enabled for recoverability.
# custom:
#   framework: hipaa
#   controls: ["164.308(a)(7)"]
#   severity: medium
package compliance.hipaa.versioning

import rego.v1

deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_s3_bucket_versioning"
    resource.values.versioning_configuration[0].status != "Enabled"
    msg := sprintf(
        "GAP-04 [HIPAA 164.308(a)(7)]: bucket '%s' versioning is not Enabled",
        [resource.values.bucket],
    )
}
