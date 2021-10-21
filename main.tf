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


resource "aws_internet_gateway" "gw_vpcone" {
  vpc_id = aws_vpc.vpcone.id

  tags = {
    Name = "internet_gateway_vpcone"
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


