variable "compartment_id" {
  description = "OCID of the compartment in which to create the security list."
  type        = string
}

variable "vcn_id" {
  description = "OCID of the VCN the security list belongs to."
  type        = string
}

variable "display_name" {
  description = "Human-readable name for the security list."
  type        = string
}

variable "ingress_rules" {
  description = "List of stateful/stateless ingress rules."
  type = list(object({
    protocol    = string
    source      = string
    source_type = optional(string, "CIDR_BLOCK")
    stateless   = optional(bool, false)
    description = optional(string)
    tcp_min     = optional(number)
    tcp_max     = optional(number)
    udp_min     = optional(number)
    udp_max     = optional(number)
  }))
  default = []
}

variable "egress_rules" {
  description = "List of stateful/stateless egress rules."
  type = list(object({
    protocol         = string
    destination      = string
    destination_type = optional(string, "CIDR_BLOCK")
    stateless        = optional(bool, false)
    description      = optional(string)
    tcp_min          = optional(number)
    tcp_max          = optional(number)
    udp_min          = optional(number)
    udp_max          = optional(number)
  }))
  default = [
    {
      protocol    = "all"
      destination = "0.0.0.0/0"
      description = "Allow all outbound traffic"
    }
  ]
}

variable "freeform_tags" {
  description = "Free-form tags applied to the security list."
  type        = map(string)
  default     = {}
}

variable "defined_tags" {
  description = "Defined tags applied to the security list, keyed as \"namespace.key\"."
  type        = map(string)
  default     = {}
}
