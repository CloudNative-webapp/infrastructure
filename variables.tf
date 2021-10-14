variable vpc_cidr_block{
    type = string
    description = "CIDR for VPC"
    // default = "10.0.0.0/16"
}
variable vpc_cidr_block2{
    type = string
    description = "CIDR for VPC2"
    // default = "10.0.0.0/16"
}

variable subnet_az_cidr{
    type = list(string)
    description = "subnet cidr for VPC1"
}

variable subnet_az_cidr2{
    type = list(string)
    description = "subnet cidr for VPC2"
}

variable subnet_az_vpc1{
    type = list(string)
    description = "subnet az for VPC1"
}

variable subnet_az_vpc2{
    type = list(string)
    description = "subnet az for VPC2"
}

variable subnet_vpcone_names{
    type = list
    description = "subnet names for VPC1"
    // default = "10.0.0.0/16"
}

variable subnet_vpctwo_names{
    type = list
    description = "subnet names for VPC2"
    // default = "10.0.0.0/16"
}

// variable subnet_cidr_block{
//     type = string
//     description = "CIDR for subnet"
//     // default = "10.0.1.0/24"
// }

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