

provider "aws" {
// for_each = var.region
  profile = var.aws_profile
  region  = var.aws_region
}

