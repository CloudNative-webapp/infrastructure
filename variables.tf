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