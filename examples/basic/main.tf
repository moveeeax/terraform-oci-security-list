provider "oci" {}

module "security_list" {
  source = "../.."

  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = "example-sl"

  ingress_rules = [
    {
      protocol    = "6"
      source      = "0.0.0.0/0"
      tcp_min     = 22
      tcp_max     = 22
      description = "Allow SSH"
    }
  ]

  freeform_tags = {
    Environment = "sandbox"
    ManagedBy   = "terraform"
  }
}

variable "compartment_id" {
  description = "Compartment OCID to deploy the example security list into."
  type        = string
}

variable "vcn_id" {
  description = "OCID of the VCN to attach the example security list to."
  type        = string
}

output "security_list_id" {
  value = module.security_list.id
}
