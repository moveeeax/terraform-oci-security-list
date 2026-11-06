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
  description = <<-EOT
    List of stateful/stateless ingress rules. `protocol` is an IANA protocol
    number as a string ("1" ICMP, "6" TCP, "17" UDP, "58" ICMPv6) or "all".
    `tcp_min`/`tcp_max` and `udp_min`/`udp_max` describe the destination port
    range and must be set as a pair; omitting them opens every port of that
    protocol. `icmp_type` (and optionally `icmp_code`) narrows an ICMP ("1") or
    ICMPv6 ("58") rule to one message type; omitting it allows every type.
  EOT
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
    icmp_type   = optional(number)
    icmp_code   = optional(number)
  }))
  default = []

  validation {
    condition = alltrue([
      for rule in var.ingress_rules :
      rule.protocol == "all" || can(regex("^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", rule.protocol))
    ])
    error_message = "Each ingress_rules.protocol must be \"all\" or an IANA protocol number 0-255 as a string, e.g. \"1\" (ICMP), \"6\" (TCP), \"17\" (UDP), \"58\" (ICMPv6)."
  }

  validation {
    condition = alltrue([
      for rule in var.ingress_rules : contains(["CIDR_BLOCK", "SERVICE_CIDR_BLOCK"], rule.source_type)
    ])
    error_message = "Each ingress_rules.source_type must be either \"CIDR_BLOCK\" or \"SERVICE_CIDR_BLOCK\"."
  }

  validation {
    condition = alltrue([
      for rule in var.ingress_rules :
      rule.source_type != "CIDR_BLOCK" || can(cidrhost(rule.source, 0))
    ])
    error_message = "Each ingress_rules.source must be a valid CIDR block (e.g. \"10.0.0.0/16\") when source_type is \"CIDR_BLOCK\"."
  }

  # try() keeps a half-specified range from raising a null-comparison error
  # before this validation gets the chance to report it properly.
  validation {
    condition = alltrue([
      for rule in var.ingress_rules :
      try(rule.tcp_min == null && rule.tcp_max == null, false) ||
      try(rule.tcp_min >= 1 && rule.tcp_max <= 65535 && rule.tcp_min <= rule.tcp_max, false)
    ])
    error_message = "ingress_rules tcp_min and tcp_max must be set together, be between 1 and 65535, and satisfy tcp_min <= tcp_max."
  }

  validation {
    condition = alltrue([
      for rule in var.ingress_rules :
      try(rule.udp_min == null && rule.udp_max == null, false) ||
      try(rule.udp_min >= 1 && rule.udp_max <= 65535 && rule.udp_min <= rule.udp_max, false)
    ])
    error_message = "ingress_rules udp_min and udp_max must be set together, be between 1 and 65535, and satisfy udp_min <= udp_max."
  }

  validation {
    condition = alltrue([
      for rule in var.ingress_rules :
      ((rule.tcp_min == null && rule.tcp_max == null) || rule.protocol == "6") &&
      ((rule.udp_min == null && rule.udp_max == null) || rule.protocol == "17")
    ])
    error_message = "ingress_rules tcp_min/tcp_max require protocol \"6\" (TCP) and udp_min/udp_max require protocol \"17\" (UDP); OCI rejects port options on any other protocol."
  }

  # OCI accepts icmp_options only on ICMP ("1") and ICMPv6 ("58"), requires a
  # type whenever a code is given, and both are 8-bit fields.
  validation {
    condition = alltrue([
      for rule in var.ingress_rules :
      (rule.icmp_type == null && rule.icmp_code == null) || contains(["1", "58"], rule.protocol)
    ])
    error_message = "ingress_rules icmp_type/icmp_code require protocol \"1\" (ICMP) or \"58\" (ICMPv6); OCI rejects ICMP options on any other protocol."
  }

  validation {
    condition = alltrue([
      for rule in var.ingress_rules :
      rule.icmp_code == null || rule.icmp_type != null
    ])
    error_message = "ingress_rules icmp_code needs icmp_type: OCI matches on a type, and a code alone has no meaning."
  }

  validation {
    condition = alltrue([
      for rule in var.ingress_rules :
      try(rule.icmp_type == null || (rule.icmp_type >= 0 && rule.icmp_type <= 255 && floor(rule.icmp_type) == rule.icmp_type), false) &&
      try(rule.icmp_code == null || (rule.icmp_code >= 0 && rule.icmp_code <= 255 && floor(rule.icmp_code) == rule.icmp_code), false)
    ])
    error_message = "ingress_rules icmp_type and icmp_code must be whole numbers between 0 and 255."
  }
}

variable "egress_rules" {
  description = <<-EOT
    List of stateful/stateless egress rules. `protocol` is an IANA protocol
    number as a string ("1" ICMP, "6" TCP, "17" UDP, "58" ICMPv6) or "all".
    `tcp_min`/`tcp_max` and `udp_min`/`udp_max` describe the destination port
    range and must be set as a pair. `icmp_type` (and optionally `icmp_code`)
    narrows an ICMP ("1") or ICMPv6 ("58") rule to one message type. Defaults to
    allowing all outbound traffic.
  EOT
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
    icmp_type        = optional(number)
    icmp_code        = optional(number)
  }))
  default = [
    {
      protocol    = "all"
      destination = "0.0.0.0/0"
      description = "Allow all outbound traffic"
    }
  ]

  validation {
    condition = alltrue([
      for rule in var.egress_rules :
      rule.protocol == "all" || can(regex("^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", rule.protocol))
    ])
    error_message = "Each egress_rules.protocol must be \"all\" or an IANA protocol number 0-255 as a string, e.g. \"1\" (ICMP), \"6\" (TCP), \"17\" (UDP), \"58\" (ICMPv6)."
  }

  validation {
    condition = alltrue([
      for rule in var.egress_rules : contains(["CIDR_BLOCK", "SERVICE_CIDR_BLOCK"], rule.destination_type)
    ])
    error_message = "Each egress_rules.destination_type must be either \"CIDR_BLOCK\" or \"SERVICE_CIDR_BLOCK\"."
  }

  validation {
    condition = alltrue([
      for rule in var.egress_rules :
      rule.destination_type != "CIDR_BLOCK" || can(cidrhost(rule.destination, 0))
    ])
    error_message = "Each egress_rules.destination must be a valid CIDR block (e.g. \"10.0.0.0/16\") when destination_type is \"CIDR_BLOCK\"."
  }

  validation {
    condition = alltrue([
      for rule in var.egress_rules :
      try(rule.tcp_min == null && rule.tcp_max == null, false) ||
      try(rule.tcp_min >= 1 && rule.tcp_max <= 65535 && rule.tcp_min <= rule.tcp_max, false)
    ])
    error_message = "egress_rules tcp_min and tcp_max must be set together, be between 1 and 65535, and satisfy tcp_min <= tcp_max."
  }

  validation {
    condition = alltrue([
      for rule in var.egress_rules :
      try(rule.udp_min == null && rule.udp_max == null, false) ||
      try(rule.udp_min >= 1 && rule.udp_max <= 65535 && rule.udp_min <= rule.udp_max, false)
    ])
    error_message = "egress_rules udp_min and udp_max must be set together, be between 1 and 65535, and satisfy udp_min <= udp_max."
  }

  validation {
    condition = alltrue([
      for rule in var.egress_rules :
      ((rule.tcp_min == null && rule.tcp_max == null) || rule.protocol == "6") &&
      ((rule.udp_min == null && rule.udp_max == null) || rule.protocol == "17")
    ])
    error_message = "egress_rules tcp_min/tcp_max require protocol \"6\" (TCP) and udp_min/udp_max require protocol \"17\" (UDP); OCI rejects port options on any other protocol."
  }

  # OCI accepts icmp_options only on ICMP ("1") and ICMPv6 ("58"), requires a
  # type whenever a code is given, and both are 8-bit fields.
  validation {
    condition = alltrue([
      for rule in var.egress_rules :
      (rule.icmp_type == null && rule.icmp_code == null) || contains(["1", "58"], rule.protocol)
    ])
    error_message = "egress_rules icmp_type/icmp_code require protocol \"1\" (ICMP) or \"58\" (ICMPv6); OCI rejects ICMP options on any other protocol."
  }

  validation {
    condition = alltrue([
      for rule in var.egress_rules :
      rule.icmp_code == null || rule.icmp_type != null
    ])
    error_message = "egress_rules icmp_code needs icmp_type: OCI matches on a type, and a code alone has no meaning."
  }

  validation {
    condition = alltrue([
      for rule in var.egress_rules :
      try(rule.icmp_type == null || (rule.icmp_type >= 0 && rule.icmp_type <= 255 && floor(rule.icmp_type) == rule.icmp_type), false) &&
      try(rule.icmp_code == null || (rule.icmp_code >= 0 && rule.icmp_code <= 255 && floor(rule.icmp_code) == rule.icmp_code), false)
    ])
    error_message = "egress_rules icmp_type and icmp_code must be whole numbers between 0 and 255."
  }
}

variable "allow_public_admin_ingress" {
  description = <<-EOT
    Permit ingress rules that expose administrative or database ports (SSH, RDP,
    WinRM, VNC, Telnet and common database ports) to 0.0.0.0/0 or ::/0. Left at
    false, the module refuses such a plan. Set it to true only when that public
    exposure is intentional.
  EOT
  type        = bool
  default     = false
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
