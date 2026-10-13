terraform {
  required_version = ">= 1.5.0"

  required_providers {
    confluent = {
      source  = "confluentinc/confluent"
      version = "~> 2.80"
    }
  }
}

provider "confluent" {
  cloud_api_key    = var.cc_cloud_api_key
  cloud_api_secret = var.cc_cloud_api_secret
}
