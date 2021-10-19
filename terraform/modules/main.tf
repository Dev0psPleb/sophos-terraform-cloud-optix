// Create VPC flow logs lambda function

resource "aws_lambda_function" "avid_vpc_logs_function" {
  count = var.should_run == true ? 1 : 0
  function_name  =  "Avid-VPC-LOGS-function"
  filename = "collector-lambda.zip"
  role = var.iam_for_lambda_arn
  handler = "collector-lambda.lambda_handler"
  timeout = "10"
  memory_size = "128"
  runtime = "python3.8"
  environment {
    variables = {
      CUSTOMER_ID = var.customer_id
      DNS_PREFIX = var.dns_prefix
      DNS_PATH = "vpclogs"
    }
  }
}

// Create cloudwatch log group to attach to vpcflow logs

resource "aws_cloudwatch_log_group" "flow_logs_avid_loggroup"{
  count = var.should_run == true ? 1 : 0
  name = "Flowlogs-Avid-LogGroup"
  retention_in_days = 1
}

// Enable flow logs for the given VPC

data "aws_vpcs" "vpcs" {
  count = var.should_run == true ? 1 : 0
}

resource "aws_flow_log" "avid_flow_logs" {
  log_destination = aws_cloudwatch_log_group.flow_logs_avid_loggroup[0].arn
  iam_role_arn   = var.iam_for_vpc_flow_arn
  traffic_type   = "ACCEPT"

  count = var.should_run == true ? length(data.aws_vpcs.vpcs[0].ids) : 0
  vpc_id = tolist(data.aws_vpcs.vpcs[0].ids)[count.index]
}

// Allow cloudwatch to invoke lambda where there are events

resource "aws_lambda_permission" "avid_vpc_logs_permission" {
  count = var.should_run == true ? 1 : 0
  statement_id   = "Avid-VPC-LOGS-permission"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.avid_vpc_logs_function[count.index].function_name
  principal      = "logs.${var.aws_region}.amazonaws.com"
  source_arn     = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:Flowlogs-Avid-LogGroup:*"
  source_account = var.aws_account_id
}

// Attach lambda to cloudwatch log group as a subscription filter

resource "aws_cloudwatch_log_subscription_filter" "lambda_stream_vpc-flow_logs_to_avid" {
  count = var.should_run == true ? 1 : 0
  depends_on = [aws_lambda_permission.avid_vpc_logs_permission]
  name            = "LambdaStream_vpc-flow-logs-to-avidsecure"
  log_group_name  = "Flowlogs-Avid-LogGroup"
  filter_pattern  = ""
  destination_arn = aws_lambda_function.avid_vpc_logs_function[count.index].arn
}
