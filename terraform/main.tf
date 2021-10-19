provider "aws" {
  region = var.aws_region
  version = "2.70.0"
}

provider "aws" {
  alias  = "us-east-1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "us-east-2"
  region = "us-east-2"
}

provider "aws" {
  alias  = "us-west-1"
  region = "us-west-1"
}

provider "aws" {
  alias  = "us-west-2"
  region = "us-west-2"
}

provider "aws" {
  alias  = "eu-west-1"
  region = "eu-west-1"
}

provider "aws" {
  alias  = "eu-west-2"
  region = "eu-west-2"
}

provider "aws" {
  alias  = "eu-west-3"
  region = "eu-west-3"
}

provider "aws" {
  alias  = "eu-central-1"
  region = "eu-central-1"
}

provider "aws" {
  alias  = "eu-north-1"
  region = "eu-north-1"
}

provider "aws" {
  alias  = "ap-south-1"
  region = "ap-south-1"
}

provider "aws" {
  alias  = "ap-southeast-1"
  region = "ap-southeast-1"
}

provider "aws" {
  alias  = "ap-southeast-2"
  region = "ap-southeast-2"
}

provider "aws" {
  alias  = "ap-northeast-1"
  region = "ap-northeast-1"
}

provider "aws" {
  alias  = "ap-northeast-2"
  region = "ap-northeast-2"
}

provider "aws" {
  alias  = "sa-east-1"
  region = "sa-east-1"
}

provider "aws" {
  alias  = "ca-central-1"
  region = "ca-central-1"
}

data "aws_iam_policy_document" "avid" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.avid_account}:root"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

resource "aws_iam_policy" "extra_permissions_policy" {
  name        = "Sophos-Optix-read-policy"
  description = "The set of extra permissions missing in the SecurityAudit"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Resource": "*",
    "Action": [
      "elasticfilesystem:DescribeMountTargetSecurityGroups",
      "elasticfilesystem:DescribeMountTargets",
      "sns:ListSubscriptions",
      "s3:GetAccountPublicAccessBlock",
      "ce:GetCostAndUsage",
      "ce:GetCostForecast",
      "ce:GetUsageForecast",
      "eks:List*",
      "detective:ListGraphs",
      "ec2:SearchTransitGatewayRoutes",
      "ec2:GetTransitGatewayRouteTableAssociations",
      "support:DescribeTrustedAdvisorCheckResult",
      "support:RefreshTrustedAdvisorCheck"
    ]
  }]
}
EOF

}

resource "aws_iam_role" "avid" {
  name               = "Avid-Role"
  assume_role_policy = data.aws_iam_policy_document.avid.json
}

resource "aws_iam_role_policy_attachment" "avid_secure_pol" {
  role       = aws_iam_role.avid.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "avid_secure_pol_extra" {
  role       = aws_iam_role.avid.name
  policy_arn = aws_iam_policy.extra_permissions_policy.arn
}

// #2. Cloudtrail configuration

// Get current account ID

data "aws_caller_identity" "current" {
}

locals {
  aws_account_id = data.aws_caller_identity.current.account_id
  s3_bucket_name = format(
    "%s%s",
    var.avid_cloudtrail_s3_bucket_prefix,
    local.aws_account_id,
  )
  pol_resource = "arn:aws:s3:::${local.s3_bucket_name}"
  act_resource = "${local.pol_resource}/AWSLogs/${local.aws_account_id}/*"
}

// Create S3 bucket for cloudtrail

resource "aws_s3_bucket" "avid_cloudtrail_bucket" {
  bucket        = local.s3_bucket_name
  force_destroy = true
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = "aws/s3"
      }
    }
  }
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "${local.pol_resource}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "${local.act_resource}",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY

}

// Configure Cloudtrail to access Cloudwatch

resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  name = "Avid-CT-to-CW"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

}

resource "aws_iam_role_policy" "cloudtrail_policy" {
  name = "cloud-traildata-policy"
  role = aws_iam_role.cloudtrail_to_cloudwatch.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailCreateLogStream",
      "Effect": "Allow",
      "Action": ["logs:CreateLogStream"],
      "Resource": [
        "arn:aws:logs:*:${local.aws_account_id}:log-group:${aws_cloudwatch_log_group.ct_avid_loggroup.id}:log-stream:*"
      ]
    },
    {
      "Sid": "AWSCloudTrailPutLogEvents",
      "Effect": "Allow",
      "Action": ["logs:PutLogEvents"],
      "Resource": [
        "arn:aws:logs:*:${local.aws_account_id}:log-group:${aws_cloudwatch_log_group.ct_avid_loggroup.id}:log-stream:*"
      ]
    }
  ]
}
EOF

}

// Create cloudwatch log group to attach to cloudtrail

resource "aws_cloudwatch_log_group" "ct_avid_loggroup" {
  name              = "CT-Avid-LogGroup"
  retention_in_days = 1
}

resource "aws_lambda_function" "avid_cloudtrail_lambda" {
  function_name = "Avid-CloudTrail-function"
  filename      = "collector-lambda.zip"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "collector-lambda.lambda_handler"
  timeout       = "10"
  memory_size   = "128"
  runtime       = "python3.8"
  environment {
    variables = {
      CUSTOMER_ID = var.customer_id
      DNS_PREFIX  = var.dns_prefix_cloudtrail
      DNS_PATH = "cloudtrail"
    }
  }
}

// Allow cloudwatch to invoke lambda where there are events

resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id   = "AllowExecutionFromCloudWatch"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.avid_cloudtrail_lambda.function_name
  principal      = "logs.${var.aws_region}.amazonaws.com"
  source_arn     = "arn:aws:logs:${var.aws_region}:${local.aws_account_id}:log-group:CT-Avid-LogGroup:*"
  source_account = local.aws_account_id
}

// Attach lambda to cloudwatch log group as a subscription filter

resource "aws_cloudwatch_log_subscription_filter" "lambda_function_logfilter" {
  depends_on      = [aws_lambda_permission.allow_cloudwatch]
  name            = "LambdaStream_cloudtrail-logs-to-avidsecure"
  log_group_name  = "CT-Avid-LogGroup"
  filter_pattern  = ""
  destination_arn = aws_lambda_function.avid_cloudtrail_lambda.arn
}

// Create cloudtrail

resource "aws_cloudtrail" "avid_cloudtrail" {
  count                         = var.avid_cloudtrail_name != "CT-AvidSecure" ? 0 : 1
  name                          = var.avid_cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.avid_cloudtrail_bucket.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.ct_avid_loggroup.arn
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_to_cloudwatch.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

resource "aws_cloudtrail" "existing_cloudtrail" {
  count                      = var.avid_cloudtrail_name != "CT-AvidSecure" ? 1 : 0
  name                       = var.avid_cloudtrail_name
  s3_bucket_name             = aws_s3_bucket.avid_cloudtrail_bucket.bucket
  cloud_watch_logs_group_arn = aws_cloudwatch_log_group.ct_avid_loggroup.arn
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cloudwatch.arn
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

// Create Lambda Role

resource "aws_iam_role" "iam_for_lambda" {
  name = "Avid-Lambda-to-CloudWatch"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

}

resource "aws_iam_role" "avid_vpc_flow_role" {
  name = "Avid-VPCFlow-Role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

}

resource "aws_iam_role_policy" "avid_vpc_flow_policy" {
  name = "Avid-VPCFlow-policy"
  role = aws_iam_role.avid_vpc_flow_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF

}

resource "aws_iam_role_policy" "avid_ct_policy" {
  name = "Avid-CT-policy"
  role = aws_iam_role.iam_for_lambda.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF

}

module "us-east-1-module" {
  source = "./modules"
  providers = {
    aws = aws.us-east-1
  }
  aws_region           = "us-east-1"
  should_run           = contains(var.region_list, "us-east-1")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "us-east-2-module" {
  source = "./modules"
  providers = {
    aws = aws.us-east-2
  }
  aws_region           = "us-east-2"
  should_run           = contains(var.region_list, "us-east-2")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "us-west-1-module" {
  source = "./modules"
  providers = {
    aws = aws.us-west-1
  }
  aws_region           = "us-west-1"
  should_run           = contains(var.region_list, "us-west-1")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "us-west-2-module" {
  source = "./modules"
  providers = {
    aws = aws.us-west-2
  }
  aws_region           = "us-west-2"
  should_run           = contains(var.region_list, "us-west-2")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "eu-west-1-module" {
  source = "./modules"
  providers = {
    aws = aws.eu-west-1
  }
  aws_region           = "eu-west-1"
  should_run           = contains(var.region_list, "eu-west-1")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "eu-west-2-module" {
  source = "./modules"
  providers = {
    aws = aws.eu-west-2
  }
  aws_region           = "eu-west-2"
  should_run           = contains(var.region_list, "eu-west-2")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "eu-west-3-module" {
  source = "./modules"
  providers = {
    aws = aws.eu-west-3
  }
  aws_region           = "eu-west-3"
  should_run           = contains(var.region_list, "eu-west-3")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "eu-central-1-module" {
  source = "./modules"
  providers = {
    aws = aws.eu-central-1
  }
  aws_region           = "eu-central-1"
  should_run           = contains(var.region_list, "eu-central-1")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "eu-north-1-module" {
  source = "./modules"
  providers = {
    aws = aws.eu-north-1
  }
  aws_region           = "eu-north-1"
  should_run           = contains(var.region_list, "eu-north-1")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "ap-south-1-module" {
  source = "./modules"
  providers = {
    aws = aws.ap-south-1
  }
  aws_region           = "ap-south-1"
  should_run           = contains(var.region_list, "ap-south-1")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "ap-southeast-1-module" {
  source = "./modules"
  providers = {
    aws = aws.ap-southeast-1
  }
  aws_region           = "ap-southeast-1"
  should_run           = contains(var.region_list, "ap-southeast-1")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "ap-southeast-2-module" {
  source = "./modules"
  providers = {
    aws = aws.ap-southeast-2
  }
  aws_region           = "ap-southeast-2"
  should_run           = contains(var.region_list, "ap-southeast-2")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "ap-northeast-1-module" {
  source = "./modules"
  providers = {
    aws = aws.ap-northeast-1
  }
  aws_region           = "ap-northeast-1"
  should_run           = contains(var.region_list, "ap-northeast-1")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "ap-northeast-2-module" {
  source = "./modules"
  providers = {
    aws = aws.ap-northeast-2
  }
  aws_region           = "ap-northeast-2"
  should_run           = contains(var.region_list, "ap-northeast-2")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "sa-east-1-module" {
  source = "./modules"
  providers = {
    aws = aws.sa-east-1
  }
  aws_region           = "sa-east-1"
  should_run           = contains(var.region_list, "sa-east-1")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

module "ca-central-1-module" {
  source = "./modules"
  providers = {
    aws = aws.ca-central-1
  }
  aws_region           = "ca-central-1"
  should_run           = contains(var.region_list, "ca-central-1")
  customer_id          = var.customer_id
  dns_prefix           = var.dns_prefix_flowlogs
  iam_for_lambda_arn   = aws_iam_role.iam_for_lambda.arn
  aws_account_id       = local.aws_account_id
  iam_for_vpc_flow_arn = aws_iam_role.avid_vpc_flow_role.arn
}

output "avid_role_arn" {
  value = aws_iam_role.avid.arn
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "external_id" {
  value = var.external_id
}
