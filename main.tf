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
      cidr_blocks      = [aws_vpc.vpcone.cidr_block]
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
}

resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "db_subnet_group"
  subnet_ids = [aws_subnet.private_subnet_vpcone[0].id,aws_subnet.private_subnet_vpcone[1].id]
  
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
  role       = "${data.aws_iam_role.iam_role.name}"
  policy_arn = aws_iam_policy.WebAppS3.arn
}

data "aws_iam_role" "iam_role" {

name = var.iam_role

}

resource "aws_iam_instance_profile" "iam_ec2_roleprofile" {
  name = "iam_ec2_roleprofile"
  role = "${data.aws_iam_role.iam_role.name}"
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


resource "aws_launch_configuration" "asg_launch_config" {
  name          = "asg_launch_config"
  image_id      = data.aws_ami.testAmi.id
  instance_type = "t2.micro"
  key_name = aws_key_pair.deployer.id
  associate_public_ip_address = true
  depends_on = [aws_db_instance.postgres_rds_instance]
  user_data = <<-EOF
  #! /bin/bash
  echo export DB_USERNAME="${var.aws_db_username}" >> /etc/environment
  echo export DB_NAME="${var.aws_db_name}" >> /etc/environment
  echo export DB_PASSWORD="${var.aws_db_password}" >> /etc/environment
  echo export DB_HOST="${aws_db_instance.postgres_rds_instance.address}" >> /etc/environment
  echo export S3_BUCKET="${aws_s3_bucket.imagebucket-prod-snehalchavan-me.id}" >> /etc/environment
  echo export PORT="${var.db_port}" >> /etc/environment
  EOF
  iam_instance_profile = "${aws_iam_instance_profile.iam_ec2_roleprofile.id}"
  security_groups = ["${aws_security_group.application.id}"]
  root_block_device {
    delete_on_termination = true
    volume_size = 20
    volume_type = "gp2"
  }
}

resource "aws_autoscaling_group" "webapp_asg" {
  desired_capacity   = 3
  max_size           = 5
  min_size           = 3
  launch_configuration = aws_launch_configuration.asg_launch_config.name
  default_cooldown = 60
  vpc_zone_identifier = [aws_subnet.subnet_vpcone[0].id,aws_subnet.subnet_vpcone[1].id,aws_subnet.subnet_vpcone[2].id]
  target_group_arns    = [ aws_lb_target_group.alb-target-group.arn ]
}

resource "aws_autoscaling_group_tag" "tagForAsg" {
  autoscaling_group_name = aws_autoscaling_group.webapp_asg.id

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
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb-target-group.arn
  }
}

data "aws_iam_role" "codeDeployServiceRole" {
  name = "CodeDeployServiceRole"
}

resource "aws_codedeploy_app" "codeDeployApp" {
  name = var.codeDeployAppName
  compute_platform = "Server"
}

resource "aws_codedeploy_deployment_group" "codeDeployGroup" {
  app_name              = aws_codedeploy_app.codeDeployApp.name
  deployment_group_name = var.codeDeployGroupName
  service_role_arn      = data.aws_iam_role.codeDeployServiceRole.arn
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


