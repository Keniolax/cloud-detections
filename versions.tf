terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region

  # Every resource carries this tag, so that if the Terraform state is lost
  # the whole lab can still be found and deleted by hand.
  default_tags {
    tags = {
      lab = "seceng-bootcamp-week-11"
    }
  }
}
