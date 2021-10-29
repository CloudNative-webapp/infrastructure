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
  subnet_id     = "${element(aws_subnet.subnet_vpcone.*.id, 0)}"
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

resource "aws_route_table_association" "subnet_rout_table_association" {
    count = length(var.subnet_az_cidr)
  subnet_id      = aws_subnet.subnet_vpcone[count.index].id
  route_table_id = aws_route_table.public_route_table_vpcone.id
}

resource "aws_security_group" "application" {
  name        = "application-security-group"
  description = "Security group for EC2 instances"
  vpc_id      = aws_vpc.vpcone.id

  tags = {
    Name = "application security group"
  }
}

resource "aws_security_group_rule" "port_one" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.application.id
}

resource "aws_security_group_rule" "port_two" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.application.id
}

resource "aws_security_group_rule" "port_three" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.application.id
}

resource "aws_security_group_rule" "port_four" {
  type              = "ingress"
  from_port         = 5000
  to_port           = 5000
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.application.id
}


resource "aws_security_group" "database" {
  name        = "database-security-group"
  description = "Security group for RDS instances"
  vpc_id      = aws_vpc.vpcone.id

  tags = {
    Name = "database security group"
  }
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
  key_name   = "mykpair"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCRmD04cW9YWYMWiQDSBKIszPE9ZAtH/Z3ShorkdkHk3tbDnTmewK6EkYRmzmItRtUFXqum1ORVZnGM7GeujuxhKhN7v0nLrAn0Xnlkbsj3fTEpFEZWuyvenEcxXeyr8HKBw+oHmDbuVTn69rKB5umDVnTayq5XkRRENxjI28bb7+zEjidtPnVibgeIfT8fXRMLNaWs/yIzL39GviqSjii1TdDYQv7gSn6XrsPKZPWg0vD3SQTb7oijXjkK9LyaVBQ9W7VKyYp+p06CciqSodmQNLpcYFZs8Tlk4PKAuxmRcLUpEnT5OrP6XQmv/ZuZkJ+GHGrfSwsV2bZNCrO3YnRd"
}

resource "aws_s3_bucket" "imagebucket-dev-snehalchavan-me" {
  bucket = "imagebucket-dev-snehalchavan-me"
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
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_instance" "ec2_instance" {
  ami           = data.aws_ami.testAmi.id 
  instance_type = "t2.micro"
  iam_instance_profile = "${aws_iam_instance_profile.iam_ec2_roleprofile.id}"
  
  disable_api_termination = false
  depends_on = [aws_db_instance.postgres_rds_instance]
  vpc_security_group_ids = ["${aws_security_group.application.id}"]
  availability_zone = var.subnet_az_vpc1[0]
  subnet_id = aws_subnet.subnet_vpcone[0].id
  user_data = "${file("user-data-db.sh")}"
  key_name= aws_key_pair.deployer.id
  root_block_device {
    delete_on_termination = true
    volume_size = 20
    volume_type = "gp2"
  }
}

data "aws_ami" "testAmi" {
  most_recent = true
  owners = ["self"]
}

resource "aws_iam_role_policy" "WebAppS3" {
  name        = "WebAppS3"
  role = "${aws_iam_role.iam_role.id}"
  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = "${file("WebAppS3.json")}"
  
}

resource "aws_iam_instance_profile" "iam_ec2_roleprofile" {
  name = "iam_ec2_roleprofile"
  role = "${aws_iam_role.iam_role.name}"
}


resource "aws_iam_role" "iam_role" {
  name                = "EC2-CSYE6225"
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

