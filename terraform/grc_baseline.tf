# ============================================================
# CGE-P Capstone — Layer 1: GRC Baseline
# Primary framework: HIPAA Security Rule
# Additive governance over the starter. Does not modify starter
# resources except where AWS requires inline config (DynamoDB).
# ============================================================

# Customer-managed key (CMK) for all PHI data stores.
# Rotation enabled per capstone Layer 1 requirement.
resource "aws_kms_key" "phi" {
  description             = "Acme Health PHI CMK (S3 uploads + DynamoDB intake)"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  tags = {
    Project   = "acme-health-intake"
    DataClass = "phi"
    ManagedBy = "terraform"
    Purpose   = "phi-encryption-cmk"
  }
}

resource "aws_kms_alias" "phi" {
  name          = "alias/acme-health-phi"
  target_key_id = aws_kms_key.phi.key_id
}

# GAP-01 | HIPAA 164.312(a)(2)(iv) — encryption at rest under a CMK you own.
# Replaces reliance on the AWS-managed SSE-S3 default.
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

# GAP-04 | HIPAA 164.308(a)(7) — contingency/recoverability. Versioning
# makes PHI object overwrites and deletes recoverable.
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}

# GAP-03 | HIPAA 164.312(e)(1) — transmission security. Deny any request
# that isn't over TLS.
resource "aws_s3_bucket_policy" "uploads_tls" {
  bucket = aws_s3_bucket.uploads.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLSRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.uploads.arn,
          "${aws_s3_bucket.uploads.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}
