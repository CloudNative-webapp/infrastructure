vpc_cidr_block    = "10.0.0.0/16"
vpc_cidr_block2    = "10.1.0.0/16"
aws_profile       = "prod"
aws_destination_cidr = "0.0.0.0/0"
aws_region = "us-east-1"

subnet_az_cidr=[
    "10.0.2.0/24",
    "10.0.3.0/24",
    "10.0.4.0/24",
]


subnet_az_vpc1=[
    "us-east-1a",
    "us-east-1b",
    "us-east-1c",
]

subnet_vpcone_names=[
    "subnet1_vpc1",
    "subnet2_vpc1",
    "subnet3_vpc1",
]


// subnet_cidr_block = "10.0.1.0/24"