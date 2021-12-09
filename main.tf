resource "aws_vpc" "vpcone" {
  cidr_block = var.vpc_cidr_block
  instance_tenancy = var.instance_tenancy
  enable_dns_support = var.enable_dns_support
  enable_dns_hostnames = var.enable_dns_hostnames
  enable_classiclink_dns_support = var.enable_classiclink_dns_support
  assign_generated_ipv6_cidr_block = var.assign_generated_ipv6_cidr_block


  tags = {
    Name = "VPC_one"
  }
}


resource "aws_subnet" "subnet_vpcone" {


  depends_on              = [aws_vpc.vpcone]

  count = length(var.subnet_az_cidr)
  vpc_id                  = aws_vpc.vpcone.id
  cidr_block              = var.subnet_az_cidr[count.index]
  availability_zone       = var.subnet_az_vpc1[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = var.subnet_vpcone_names[count.index]
  }
}

resource "aws_subnet" "private_subnet_vpcone" {

  depends_on              = [aws_vpc.vpcone]
  count = length(var.subnet_az_cidr_private)
  vpc_id                  = aws_vpc.vpcone.id
  cidr_block              = var.subnet_az_cidr_private[count.index]
  availability_zone       = var.subnet_az_vpc1_private[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "private_subnet"
  }
}


resource "aws_internet_gateway" "gw_vpcone" {
  vpc_id = aws_vpc.vpcone.id

  tags = {
    Name = "internet_gateway_vpcone"
  }
}

resource "aws_eip" "nat_eip" {
  vpc        = true
  depends_on = [aws_internet_gateway.gw_vpcone]
}

resource "aws_nat_gateway" "nat" {
  allocation_id = "${aws_eip.nat_eip.id}"
  subnet_id     = aws_subnet.private_subnet_vpcone[0].id
  depends_on    = [aws_internet_gateway.gw_vpcone]
  tags = {
    Name        = "nat"
  }
}

resource "aws_route" "public_route" {
    route_table_id            = aws_route_table.public_route_table_vpcone.id
      destination_cidr_block = var.aws_destination_cidr
      gateway_id = aws_internet_gateway.gw_vpcone.id
      depends_on                = [aws_route_table.public_route_table_vpcone]
    }

resource "aws_route_table" "public_route_table_vpcone" {
  vpc_id = aws_vpc.vpcone.id

  tags = {
    Name = "public_route_table_vpcone"
  }
}

resource "aws_route_table_association" "private_subnet_rout_table_association" {
    count = length(var.subnet_az_cidr_private)
  subnet_id      = aws_subnet.private_subnet_vpcone[count.index].id
  route_table_id = aws_route_table.public_route_table_vpcone.id
}

resource "aws_route_table_association" "subnet_rout_table_association" {
    count = length(var.subnet_az_cidr)
  subnet_id      = aws_subnet.subnet_vpcone[count.index].id
  route_table_id = aws_route_table.public_route_table_vpcone.id
}

resource "aws_security_group" "application" {
  name        = "application-security-group"
  description = "Security group for EC2 instances"
  vpc_id      = aws_vpc.vpcone.id

  ingress = [
    {
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      description      = "TLS from VPC"
      cidr_blocks      = []
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = [aws_security_group.loadbalancer-security-group.id]
      self             = false
    },
    {
      from_port        = 22
      to_port          = 22
      protocol         = "tcp"
      description      = "SSH from VPC"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = [aws_security_group.loadbalancer-security-group.id]
      self             = false
    },
    {
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      description      = "HTTP from VPC"
      cidr_blocks      = []
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = [aws_security_group.loadbalancer-security-group.id]
      self             = false
    },
    {
      description      = "NODE application"
      from_port        = 3000
      to_port          = 3000
      protocol         = "tcp"
      cidr_blocks      = []
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = [aws_security_group.loadbalancer-security-group.id]
      self             = false
    }
  ]
  egress = [
    {
      description      = "HTTP"
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "HTTPS"
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "SQL"
      from_port        = 5432
      to_port          = 5432
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
  ]

  tags = {
    Name = "application security group"
  }

}


resource "aws_security_group" "database" {
  name        = "database-security-group"
  description = "Security group for RDS instances"
  vpc_id      = aws_vpc.vpcone.id

  tags = {
    Name = "database security group"
  }
}

resource "aws_security_group_rule" "port_db_outbound" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [aws_vpc.vpcone.cidr_block]
  security_group_id = aws_security_group.database.id
  // source_security_group_id = aws_security_group.application.id
}

resource "aws_security_group_rule" "port_db" {
  type              = "ingress"
  from_port         = var.db_port
  to_port           = var.db_port
  protocol          = "tcp"
  cidr_blocks       = [aws_vpc.vpcone.cidr_block]
  security_group_id = aws_security_group.database.id
  // source_security_group_id = aws_security_group.application.id
}

resource "aws_db_instance" "postgres_rds_instance" {
  engine               = var.engine
  allocated_storage    = 10
  engine_version       = var.engine_version
  instance_class       = var.aws_db_instance_class
  multi_az             = "false"
  identifier           = "csye6225"
  name                 = var.aws_db_name
  username             = var.aws_db_username
  password             = var.aws_db_password
  parameter_group_name = aws_db_parameter_group.csye6225_db_parametergroup.id
  publicly_accessible  = "false"
  skip_final_snapshot  = true
  db_subnet_group_name = aws_db_subnet_group.db_subnet_group.id
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
  backup_retention_period   = var.backup_retention_period
  availability_zone = var.subnet_az_vpc1_private[0]
  kms_key_id = aws_kms_key.keyForRdsEncryption.arn
  storage_encrypted = true
}

data "aws_db_instance" "masterDB" {
  db_instance_identifier = "csye6225"
  depends_on             = [aws_db_instance.postgres_rds_instance]
}


resource "aws_db_instance" "rds_replica" {
  engine               = var.engine
  engine_version       = var.engine_version
  instance_class       = var.aws_db_instance_class
  multi_az             = "false"
  identifier           = "replica-for-rds"
  name                 = var.aws_db_name
  parameter_group_name = aws_db_parameter_group.csye6225_db_parametergroup.id
  publicly_accessible  = "false"
  skip_final_snapshot  = true
  replicate_source_db = data.aws_db_instance.masterDB.db_instance_arn
  availability_zone = var.subnet_az_vpc1_private[2]
}

resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "db_subnet_group"
  subnet_ids = [aws_subnet.private_subnet_vpcone[0].id,aws_subnet.private_subnet_vpcone[1].id,aws_subnet.private_subnet_vpcone[2].id]
  
  tags = {
    Name = "My DB subnet group"
  }
}

output "rds_hostname" {
  value       = aws_db_instance.postgres_rds_instance.address
  description = "DB Master hostname"
}

output "rds_port" {
description = "RDS instance port"
value = aws_db_instance.postgres_rds_instance.port
sensitive = true
}


resource "aws_db_parameter_group" "csye6225_db_parametergroup" {
  name   = "csye6225-db-parametergroup"
  family = "postgres13"
  

  parameter {
    name = "application_name"
    value = "postgres logs reports"
  }

  parameter {
    name = "rds.force_ssl"
    value = 1
  }

}

resource "aws_kms_key" "mykey" {
  description             = "This key is used to encrypt bucket objects"
  deletion_window_in_days = 10
}

resource "aws_key_pair" "deployer" {
  key_name   = "mypair"
  public_key = var.aws_public_key
}

resource "aws_s3_bucket" "imagebucket-prod-snehalchavan-me" {
  bucket = "imagebucket-prod-snehalchavan-me"
  acl    = "private"
  force_destroy = true

  lifecycle_rule {
    id      = "log"
    enabled = true

    prefix = "log/"

    tags = {
      rule      = "log"
      autoclean = "true"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "block_public_access" {
  bucket = aws_s3_bucket.imagebucket-prod-snehalchavan-me.id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}


data "aws_ami" "testAmi" {
  most_recent = true
  // owners = ["self"]
  owners = [var.ownerAcc,var.ownerAcc1]
}


resource "aws_iam_policy" "WebAppS3" {
  name        = "WebAppS3"
  description = "IAM Policy"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
                "s3:ListAllMyBuckets", 
              "s3:GetBucketLocation",
              "s3:GetObject",
              "s3:PutObject",
              "s3:DeleteObject"
            ],
      "Effect": "Allow",
      "Resource": ["arn:aws:s3:::${aws_s3_bucket.imagebucket-prod-snehalchavan-me.id}",
                "arn:aws:s3:::${aws_s3_bucket.imagebucket-prod-snehalchavan-me.id}/*"]
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = aws_iam_role.CodeDeployServiceRole.name
  policy_arn = aws_iam_policy.WebAppS3.arn
}


resource "aws_iam_instance_profile" "iam_ec2_roleprofile" {
  name = "iam_ec2_roleprofile"
  role = aws_iam_role.CodeDeployEC2ServiceRole.name
}

resource "aws_iam_role_policy_attachment" "sns_policy_attachment" {
  policy_arn = aws_iam_policy.sns_iam_policy.arn
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
}

data "aws_route53_zone" "selected" {
  name         = var.domainName
  private_zone = false
}


resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = "${data.aws_route53_zone.selected.name}"
  type    = "A"
  
  alias {
    name                   = aws_lb.Application-Load-Balancer.dns_name
    zone_id                = aws_lb.Application-Load-Balancer.zone_id
    evaluate_target_health = true
  }
}

resource "aws_launch_template" "asg_launch_template" {
  depends_on = [aws_db_instance.postgres_rds_instance]
  name = "asg_launch_template"
  key_name = var.keyname
   iam_instance_profile {
    name = aws_iam_instance_profile.iam_ec2_roleprofile.name
  }
  image_id                    = data.aws_ami.testAmi.id
  instance_type               = "t2.micro"
  vpc_security_group_ids      = [aws_security_group.application.id]
  user_data = base64encode(
    <<-EOF
		#! /bin/bash
      echo export DB_USERNAME="${var.aws_db_username}" >> /etc/environment
      echo export DB_NAME="${var.aws_db_name}" >> /etc/environment
      echo export DB_PASSWORD="${var.aws_db_password}" >> /etc/environment
      echo export DB_HOST="${aws_db_instance.postgres_rds_instance.address}" >> /etc/environment
      echo export S3_BUCKET="${aws_s3_bucket.imagebucket-prod-snehalchavan-me.id}" >> /etc/environment
      echo export PORT="${var.db_port}" >> /etc/environment
      echo export TOPIC_ARN="${aws_sns_topic.user_sns_topic.arn}" >> /etc/environment
      echo export domain_name="${var.domainName}" >> /etc/environment
      echo export DB_HOST_REPLICA="${aws_db_instance.rds_replica.address}" >> /etc/environment
      EOF
  )
  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = 20
      volume_type           = "gp2"
      delete_on_termination = true
      encrypted = true
      kms_key_id = aws_kms_key.keyForEC2Encryption.arn
    }
  }
}

resource "aws_autoscaling_group" "webapp_asg" {
  desired_capacity   = 3
  max_size           = 5
  min_size           = 3
  launch_template {
    id      = aws_launch_template.asg_launch_template.id
    version = aws_launch_template.asg_launch_template.latest_version
  }
  default_cooldown = 60
  vpc_zone_identifier = [aws_subnet.subnet_vpcone[0].id,aws_subnet.subnet_vpcone[1].id,aws_subnet.subnet_vpcone[2].id]
  target_group_arns    = [ aws_lb_target_group.alb-target-group.arn ]
  tag {
    key   = "Name"
    value = "webapp"

    propagate_at_launch = true
  }
}


resource "aws_autoscaling_policy" "scaleUpPolicy" {
  name                   = "scaleUpPolicy"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.webapp_asg.name
}

resource "aws_autoscaling_policy" "scaleDownPolicy" {
  name                   = "scaleDownPolicy"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.webapp_asg.name
}

resource "aws_cloudwatch_metric_alarm" "Alarm-CPU-High" {
  alarm_name          = "Alarm-CPU-High"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "5"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.webapp_asg.name
  }

  alarm_description = "This metric monitors ec2 cpu utilization > 5%"
  alarm_actions     = [aws_autoscaling_policy.scaleUpPolicy.arn]
}

resource "aws_cloudwatch_metric_alarm" "Alarm-CPU-Low" {
  alarm_name          = "Alarm-CPU-Low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "3"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.webapp_asg.name
  }

  alarm_description = "This metric monitors ec2 cpu utilization < 3%"
  alarm_actions     = [aws_autoscaling_policy.scaleDownPolicy.arn]
}

resource "aws_security_group" "loadbalancer-security-group" {
  name        = "loadbalancer-security-group"
  description = "Application load balancer security group"
  vpc_id      = "${aws_vpc.vpcone.id}"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress{
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    }

   ingress{
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    
    }

    ingress{
    description = "Postgres"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    }

  # Allow all outbound traffic.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Application load balancer security group"
    Environment = var.aws_profile
  }
}


#Application load balancer
resource "aws_lb" "Application-Load-Balancer" {
  name               = "Application-Load-Balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.loadbalancer-security-group.id]
  subnets            = [aws_subnet.subnet_vpcone[0].id,aws_subnet.subnet_vpcone[1].id,aws_subnet.subnet_vpcone[2].id]
  ip_address_type = "ipv4"
  tags = {
    Environment = var.aws_profile
  }
}

//target group for ALB
resource "aws_lb_target_group" "alb-target-group" {
  name     = "alb-target-group"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpcone.id

  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    port                = "3000"
    //still not sure about path
    path              = "/healthstatus" 
    interval            = 30
    matcher = "200"
  }
}

resource "aws_lb_listener" "alb-listener" {
  load_balancer_arn = aws_lb.Application-Load-Balancer.arn
  port              = "443"
  protocol          = "HTTPS"
  // ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = data.aws_acm_certificate.certificateForProd.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb-target-group.arn
  }
}


resource "aws_codedeploy_app" "codeDeployApp" {
  name = var.codeDeployAppName
  compute_platform = "Server"
}

resource "aws_codedeploy_deployment_group" "codeDeployGroup" {
  app_name              = aws_codedeploy_app.codeDeployApp.name
  deployment_group_name = var.codeDeployGroupName
  service_role_arn      = aws_iam_role.CodeDeployServiceRole.arn
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  autoscaling_groups = ["${aws_autoscaling_group.webapp_asg.name}"]
  load_balancer_info {
    target_group_info {
      name = aws_lb_target_group.alb-target-group.name
    }
  }
  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }
  ec2_tag_filter {
    key   = "Name"
    type  = "KEY_AND_VALUE"
    value = "webapp"
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }

  alarm_configuration {
    alarms  = ["deploy-alarm"]
    enabled = true
  }
  depends_on = [aws_codedeploy_app.codeDeployApp]
}

# IAM policy for SNS
resource "aws_iam_policy" "sns_iam_policy" {
  name = "ec2_iam_policy_for_EC2"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "SNS:Publish"
      ],
      "Resource": "${aws_sns_topic.user_sns_topic.arn}"
    }
  ]
}
EOF
}

resource "aws_sns_topic" "user_sns_topic" {
  name = "user_sns_topic"
}

resource "aws_sns_topic_policy" "topic_policy_sns" {
  arn = aws_sns_topic.user_sns_topic.arn

  policy = data.aws_iam_policy_document.sns_topic_policy.json
}

data "aws_iam_policy_document" "sns_topic_policy" {
  policy_id = "__default_policy_ID"

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = [
        var.ownerAcc1,
      ]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      aws_sns_topic.user_sns_topic.arn,
    ]

    sid = "__default_statement_ID"
  }
}

resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name  = "/aws/lambda/${aws_lambda_function.user_lambda.function_name}"
}

resource "aws_lambda_permission" "with_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.user_lambda.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.user_sns_topic.arn
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.user_sns_topic.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.user_lambda.arn
}

resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"

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

resource "aws_iam_policy" "lambda_policy" {
  name        = "lambda_policy"
  description = "Policy for SES and DynamoDB"
  policy      = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
        {
           "Effect": "Allow",
           "Action": "logs:CreateLogGroup",
           "Resource": "arn:aws:logs:${var.aws_region}:${var.AWS_ACCOUNT_ID}:*"
       },
        {
           "Effect": "Allow",
           "Action": [
               "logs:CreateLogStream",
               "logs:PutLogEvents"
           ],
           "Resource": [
              "arn:aws:logs:${var.aws_region}:${var.AWS_ACCOUNT_ID}:log-group:/aws/lambda/${aws_lambda_function.user_lambda.function_name}:*"
          ]
       },
       {
         "Sid": "LambdaDynamoDBAccess",
         "Effect": "Allow",
         "Action": [
             "dynamodb:GetItem",
             "dynamodb:PutItem",
             "dynamodb:UpdateItem",
             "dynamodb:Scan",
             "dynamodb:DeleteItem"
         ],
         "Resource": "arn:aws:dynamodb:${var.aws_region}:${var.ownerAcc1}:table/${var.dynamoDBName}"
       },
       {
         "Sid": "LambdaSESAccess",
         "Effect": "Allow",
         "Action": [
             "ses:VerifyEmailAddress",
             "ses:SendEmail",
             "ses:SendRawEmail"
         ],
         "Resource": "*",
          "Condition":{
            "StringEquals":{
              "ses:FromAddress":"${var.fromAddress}@${var.domainName}"
            }
          }
       }
   ]
}
 EOF
}

# Attach the policy for IAM Lambda role
resource "aws_iam_role_policy_attachment" "lambda_role_policy_attach" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

#Lambda function resource
resource "aws_lambda_function" "user_lambda" {
  filename      = "lambda_function_payload.zip"
  function_name = "lambda_function_send_email"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.handler"

  # The filebase64sha256() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
  # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
  source_code_hash = filebase64sha256("lambda_function_payload.zip")

  runtime = "nodejs14.x"

  environment {
    variables = {
      foo = "bar"
    }
  }
}

resource "aws_dynamodb_table" "dynamodb-table" {
  name           = var.dynamoDBName
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "one-time-token"

  attribute {
    name = "one-time-token"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }


  tags = {
    Name        = var.dynamoDBName
  }
}

resource "aws_iam_policy" "dynamoDbEc2Policy"{
  name = "DynamoDb-Ec2"
  description = "ec2 will be able to talk to dynamodb"
  policy = <<-EOF
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [      
              "dynamodb:List*",
              "dynamodb:DescribeReservedCapacity*",
              "dynamodb:DescribeLimits",
              "dynamodb:DescribeTimeToLive"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:BatchGet*",
                "dynamodb:DescribeStream",
                "dynamodb:DescribeTable",
                "dynamodb:Get*",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:BatchWrite*",
                "dynamodb:CreateTable",
                "dynamodb:Delete*",
                "dynamodb:Update*",
                "dynamodb:PutItem"
            ],
            "Resource": "arn:aws:dynamodb:${var.aws_region}:${var.ownerAcc1}:table/${var.dynamoDBName}"
        }
    ]
    }
    EOF
  }

resource "aws_iam_role_policy_attachment" "attachDynamoDbPolicyToRole" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.dynamoDbEc2Policy.arn
}

resource "aws_s3_bucket" "lambda_bucket" {
  bucket = var.lambdaBucket
  acl    = "private"
  force_destroy = true

  lifecycle_rule {
    id      = "log"
    enabled = true

    prefix = "log/"

    tags = {
      rule      = "log"
      autoclean = "true"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "block_public_access_lambda" {
  bucket = aws_s3_bucket.lambda_bucket.id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}


resource "aws_iam_policy" "CodeDeploy-EC2-S3" {
  name        = "CodeDeploy-EC2-S3"
  description = "AMI Policy for code deploy S3"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:Get*",
                "s3:List*",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion"
            ],
            "Effect": "Allow",
            "Resource": [ "arn:aws:s3:::${var.S3_BucketName}/*",
            "arn:aws:s3:::${var.lambdaBucket}/*",
                "arn:aws:s3:::${var.s3bucketNameImage}/*"]
        }
    ]
}
EOF
}

resource "aws_iam_policy" "GH-Upload-To-S3" {
  name        = "GH-Upload-To-S3"
  description = "AMI Policy upload to S3"
  policy      = <<EOF
{
 "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:Get*",
                "s3:List*",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion"
            ],
            "Resource": [
                "arn:aws:s3:::${var.S3_BucketName}",
                "arn:aws:s3:::${var.S3_BucketName}/*",
                "arn:aws:s3:::${var.lambdaBucket}",
                "arn:aws:s3:::${var.lambdaBucket}/*"
            ]
        }
    ] 
}
EOF
}

resource "aws_iam_policy" "GH-Code-Deploy" {
  name        = "GH-Code-Deploy"
  description = "AMI Policy to call deploy api"
  policy      = <<EOF
{
 "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.aws_region}:${var.AWS_ACCOUNT_ID}:application:${var.CODE_DEPLOY_APPLICATION_NAME}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.aws_region}:${var.AWS_ACCOUNT_ID}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.aws_region}:${var.AWS_ACCOUNT_ID}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.aws_region}:${var.AWS_ACCOUNT_ID}:deploymentconfig:CodeDeployDefault.AllAtOnce"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_policy" "gh-ec2-ami" {
  name        = "gh-ec2-ami"
  description = "AMI Policy EC2"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "*"
    }
  ]
}

EOF
}

resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name = "CodeDeployEC2ServiceRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

data "aws_iam_user" "appUser" {
  user_name = var.username_iam
}

resource "aws_iam_role_policy_attachment" "CodeDeploy-EC2-S3" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn =  aws_iam_policy.CodeDeploy-EC2-S3.arn
}

resource "aws_iam_role_policy_attachment" "CloudWatchAgentServer" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Attach the policy for CodeDeploy role for webapp
resource "aws_iam_role_policy_attachment" "AWSCodeDeployRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role       = "${aws_iam_role.CodeDeployServiceRole.name}"
}

resource "aws_iam_user_policy_attachment" "ec2_ami_policy_attach" {
  user       = data.aws_iam_user.appUser.user_name
  policy_arn = "${aws_iam_policy.gh-ec2-ami.arn}"
}

resource "aws_iam_user_policy_attachment" "GH_Code_policy_attach" {
  user       = data.aws_iam_user.appUser.user_name
  policy_arn = "${aws_iam_policy.GH-Code-Deploy.arn}"
}

resource "aws_iam_user_policy_attachment" "code_upload_policy_attach" {
  user       = data.aws_iam_user.appUser.user_name
  policy_arn = "${aws_iam_policy.GH-Upload-To-S3.arn}"
}


resource "aws_iam_policy" "Update-lambda-function" {
  name        = "Update-lambda-function"
  description = "Policy to update lambda function"
  policy      = <<EOF
{
 "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": "lambda:UpdateFunctionCode",
            "Resource": "arn:aws:lambda:${var.aws_region}:${var.AWS_ACCOUNT_ID}:function:lambda_function_send_email"
        }
    ] 
}
EOF
}

resource "aws_iam_user_policy_attachment" "Update-lambda-function_policy_attach" {
  user       = data.aws_iam_user.appUser.user_name
  policy_arn = "${aws_iam_policy.Update-lambda-function.arn}"
}


resource "aws_kms_key" "keyForEC2Encryption" {
  description             = "EC2 key for encryption"
  deletion_window_in_days = 10
  policy                  = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::${var.AWS_ACCOUNT_ID}:root"},
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {"AWS": [
        "arn:aws:iam::${var.AWS_ACCOUNT_ID}:user/${var.username_iam}",
        "arn:aws:iam::${var.AWS_ACCOUNT_ID}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
      ]},
      "Action": [
        "kms:Create*",
        "kms:Describe*",
        "kms:Enable*",
        "kms:List*",
        "kms:Put*",
        "kms:Update*",
        "kms:Revoke*",
        "kms:Disable*",
        "kms:Get*",
        "kms:Delete*",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion"
      ],
      "Resource": "*"
    },
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {"AWS": [
        "arn:aws:iam::${var.AWS_ACCOUNT_ID}:user/${var.username_iam}",
        "arn:aws:iam::${var.AWS_ACCOUNT_ID}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
        "arn:aws:iam::${var.AWS_ACCOUNT_ID}:root"
      ]},
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {"AWS": [
        "arn:aws:iam::${var.AWS_ACCOUNT_ID}:user/${var.username_iam}",
        "arn:aws:iam::${var.AWS_ACCOUNT_ID}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
        "arn:aws:iam::${var.AWS_ACCOUNT_ID}:root"
      ]},
      "Action": [
        "kms:CreateGrant",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ],
      "Resource": "*",
      "Condition": {"Bool": {"kms:GrantIsForAWSResource": "true"}}
    }
  ]
}
EOF
}

resource "aws_kms_key" "keyForRdsEncryption" {
  description             = "RDS key for encryption"
  deletion_window_in_days = 10
}

data "aws_acm_certificate" "certificateForProd" {
  domain   = var.domainName
  statuses = ["ISSUED"]
}

data "aws_kms_key" "by_id" {
  key_id = aws_kms_key.keyForEC2Encryption.id
}
