// locals{
//     subnet_az_cidr={
//         "us-east-1a"="10.0.2.0/24",
//         "us-east-1b"="10.0.3.0/24",
//         "us-east-1c"="10.0.4.0/24",

//     }

//     subnet_az_cidr2={
//         "us-east-1d"="10.1.2.0/24",
//         "us-east-1e"="10.1.3.0/24",
//         "us-east-1f"="10.1.4.0/24",

//     }

// }


resource "aws_vpc" "vpcone" {
  cidr_block = var.vpc_cidr_block
  tags = {
    Name = "VPC_one"
  }
}



resource "aws_subnet" "subnet_vpcone" {


  depends_on              = [aws_vpc.vpcone]

  // for_each = local.subnet_az_cidr
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


