provider "oci" {}

locals {
  # The rule OCI puts in every default security list: ICMP type 3 code 4
  # ("fragmentation needed") from anywhere, which path MTU discovery depends on.
  # It opens nothing else, unlike a bare protocol "1" rule that admits every
  # ICMP type including echo requests.
  icmp_path_mtu_discovery = {
    protocol    = "1"
    source      = "0.0.0.0/0"
    icmp_type   = 3
    icmp_code   = 4
    description = "Allow ICMP fragmentation-needed for path MTU discovery"
  }
}

module "security_list" {
  source = "../.."

  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = "example-sl"

  ingress_rules = [
    {
      protocol    = "6"
      source      = "0.0.0.0/0"
      tcp_min     = 443
      tcp_max     = 443
      description = "Allow HTTPS from the internet"
    },
    {
      # SSH is deliberately scoped to the administrative network. Pointing this
      # at 0.0.0.0/0 fails the module's plan-time guard unless
      # allow_public_admin_ingress is set to true.
      protocol    = "6"
      source      = var.ssh_ingress_cidr
      tcp_min     = 22
      tcp_max     = 22
      description = "Allow SSH from the admin network"
    },
    local.icmp_path_mtu_discovery,
    {
      protocol    = "1"
      source      = "10.0.0.0/16"
      icmp_type   = 8
      description = "Allow echo requests (ping) from inside the VCN"
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

variable "ssh_ingress_cidr" {
  description = "CIDR block allowed to reach SSH on instances using this security list."
  type        = string
  default     = "10.0.0.0/16"
}

output "security_list_id" {
  value = module.security_list.id
}
