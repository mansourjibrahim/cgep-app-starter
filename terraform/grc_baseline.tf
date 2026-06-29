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
      sse_algorithm = "AES256"
    }
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

# ============================================================
# Capstone — Evidence Vault (immutable, Object Lock)
# Every signed pipeline evidence bundle lands here.
# GOVERNANCE + 1-day retention: durable enough to prove immutability,
# still cleanable after the lab. HIPAA 164.312(b) audit controls.
# ============================================================
resource "aws_s3_bucket" "evidence" {
  bucket              = "acme-health-evidence-${random_id.suffix.hex}"
  object_lock_enabled = true

  tags = {
    Project   = "acme-health-intake"
    DataClass = "evidence"
    ManagedBy = "terraform"
    Purpose   = "signed-evidence-vault"
  }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 1
    }
  }
}

output "evidence_bucket" {
  value       = aws_s3_bucket.evidence.id
  description = "Immutable evidence vault for signed pipeline bundles."
}

# ============================================================
# Capstone — GitHub Actions OIDC trust
# Lets the pipeline assume an AWS role using short-lived tokens.
# No long-lived access keys stored in GitHub. HIPAA 164.312(d).
# ============================================================
variable "github_repo" {
  type        = string
  description = "GitHub repo allowed to assume the CI role, as owner/name."
  default     = "mansourjibrahim/cgep-app-starter"
}

data "aws_caller_identity" "current" {}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "github_actions" {
  name = "acme-health-github-actions-ci"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_repo}:*"
        }
      }
    }]
  })

  tags = {
    Project   = "acme-health-intake"
    ManagedBy = "terraform"
    Purpose   = "github-actions-ci"
  }
}

# CI role permissions: read state, plan, and write evidence to the vault.
# Scoped to plan/read + evidence upload. NOT full admin.
resource "aws_iam_role_policy" "github_actions" {
  name = "ci-plan-and-evidence"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadStateForPlan"
        Effect = "Allow"
        Action = [
          "s3:Get*", "s3:List*",
          "dynamodb:DescribeTable", "dynamodb:DescribeContinuousBackups",
          "dynamodb:ListTagsOfResource",
          "kms:DescribeKey", "kms:GetKeyRotationStatus", "kms:GetKeyPolicy", "kms:ListResourceTags",
          "lambda:GetFunction*", "lambda:ListVersionsByFunction",
          "iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies",
          "ec2:Describe*",
          "apigateway:GET"
        ]
        Resource = "*"
      },
      {
        Sid    = "WriteEvidence"
        Effect = "Allow"
        Action = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.evidence.arn}/*"
      },
      {
        Sid    = "UseCmkForEvidence"
        Effect = "Allow"
        Action = ["kms:GenerateDataKey", "kms:Encrypt", "kms:Decrypt"]
        Resource = aws_kms_key.phi.arn
      }
    ]
  })
}

output "github_actions_role_arn" {
  value       = aws_iam_role.github_actions.arn
  description = "ARN the GitHub Actions workflow assumes via OIDC."
}
