variable "a_permission_prompt" {
  description = <<-PROMPTDESCRIPTION
Review the Cloud Optix <online help https://docs.sophos.com/pcg/optix/help/en-us/pcg/optix/tasks/AddAWSScript.html> before running the script. We recommend that you run the script using an IAM \"Administrator\" role. However, if you want to run the script with limited permissions, you can use the specific permissions <https://docs.sophos.com/pcg/optix/help/en-us/pcg/optix/concepts/AWSScriptPermissions.html> provided, to create a custom role. 

Review above text and accept it by pressing any key followed by enter or press Ctrl+C to cancel script.
-
PROMPTDESCRIPTION

}

variable "aws_region" {
}

variable "avid_account" {
  type    = string
  default = "195990147830"
}

variable "external_id" {
}

variable "avid_cloudtrail_name" {
  type    = string
  default = "CT-AvidSecure"
}

variable "avid_cloudtrail_s3_bucket_prefix" {
  type    = string
  default = "avid-cloudtrail-"
}

variable "customer_id" {
  type = string
}

variable "dns_prefix_cloudtrail" {
  type = string
}

variable "dns_prefix_flowlogs" {
  type = string
}

variable "region_list" {
  type = list(string)
  default = [
    "us-west-1",
    "us-west-2",
    "us-east-1",
    "us-east-2",
    "eu-west-1",
    "eu-west-2",
    "eu-central-1",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "sa-east-1",
    "ca-central-1",
    "eu-west-3",
    "eu-north-1",
  ]
}

