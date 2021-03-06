variable vpc_cidr_block{
    type = string
    description = "CIDR for VPC"
}

variable instance_tenancy{
    type = string
    description = "instance_tenancy for VPC"
}

variable enable_dns_support{
    type = string
    description = "dns_support for VPC"
}

variable enable_dns_hostnames{
    type = string
    description = "dns_hostnames for VPC"
}

variable enable_classiclink_dns_support{
    type = string
    description = "classiclink_dns_support for VPC"
}

variable assign_generated_ipv6_cidr_block{
    type = string
    description = "ipv6_cidr_block for VPC"
}

variable subnet_az_cidr{
    type = list(string)
    description = "subnet cidr for VPC1"
}

variable subnet_az_cidr_private{
    type = list(string)
    description = "private subnet cidr for VPC1"
}

variable subnet_az_vpc1_private{
    type = list(string)
    description = "private subnet az for VPC1"
}

variable subnet_az_vpc1{
    type = list(string)
    description = "subnet az for VPC1"
}

variable subnet_vpcone_names{
    type = list
    description = "subnet names for VPC1"
}

variable aws_profile{
    type = string
    description = ""
}

variable aws_destination_cidr{
    type = string
    description = ""
}

variable aws_region{
    type = string
    description="AWS region"
}

variable aws_db_name{
    type = string
    description="name for rds"
}

variable aws_db_username{
    type = string
    description="username for rds"
}

variable aws_db_password{
    type = string
    description="password for rds"
}

variable aws_db_instance_class{
    type = string
    description="instance class for rds"
}

variable engine_version{
    type = string
    description="engine version for rds"
}

variable engine{
    type = string
    description="engine for rds"
}

variable db_port{
    type = number
    description="database port id"
}

variable aws_public_key{
    type = string
    description="ssh public key"
}

variable iam_role{
    type = string
    description="role for ec2"
}

variable "domainName" {
  description = "Domain name"
  type        = string
}

variable "ownerAcc" {
  description = "Owner acc"
  type        = string
}

variable "ownerAcc1" {
  description = "Owner acc1"
  type        = string
}

variable "codeDeployGroupName" {
  description = "Code deploy group name"
  type        = string
}

variable "codeDeployAppName" {
  description = "Code deploy app name"
  type        = string
}

variable "fromAddress" {
  description = "Address to send email to"
  type        = string
}

variable "dynamoDBName"{
    description = "DynamoDB name"
    type        = string
}

variable "backup_retention_period" {
  type = string
}

variable "availability_zone" {
  type = string
}

variable "lambdaBucket"{
    type = string
}

variable "S3_BucketName" {
  description = "S3 Bucket Name"
  type        = string
}

variable "s3bucketNameImage" {
  description = "S3 Bucket Name image"
  type        = string
}

variable "AWS_ACCOUNT_ID" {
  description = "Aws account ID"
  type        = string
}

variable "username_iam" {
  description = "Aws user name"
  type        = string
}

variable "CODE_DEPLOY_APPLICATION_NAME" {
  description = "code deploy application name"
  type        = string
}

variable "keyname"{
  description = "Key name"
  type        = string
}