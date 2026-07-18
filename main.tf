resource "oci_core_security_list" "this" {
  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = var.display_name

  dynamic "ingress_security_rules" {
    for_each = var.ingress_rules
    content {
      protocol    = ingress_security_rules.value.protocol
      source      = ingress_security_rules.value.source
      source_type = ingress_security_rules.value.source_type
      stateless   = ingress_security_rules.value.stateless
      description = ingress_security_rules.value.description

      dynamic "tcp_options" {
        for_each = ingress_security_rules.value.tcp_min != null ? [1] : []
        content {
          min = ingress_security_rules.value.tcp_min
          max = ingress_security_rules.value.tcp_max
        }
      }

      dynamic "udp_options" {
        for_each = ingress_security_rules.value.udp_min != null ? [1] : []
        content {
          min = ingress_security_rules.value.udp_min
          max = ingress_security_rules.value.udp_max
        }
      }
    }
  }

  dynamic "egress_security_rules" {
    for_each = var.egress_rules
    content {
      protocol         = egress_security_rules.value.protocol
      destination      = egress_security_rules.value.destination
      destination_type = egress_security_rules.value.destination_type
      stateless        = egress_security_rules.value.stateless
      description      = egress_security_rules.value.description

      dynamic "tcp_options" {
        for_each = egress_security_rules.value.tcp_min != null ? [1] : []
        content {
          min = egress_security_rules.value.tcp_min
          max = egress_security_rules.value.tcp_max
        }
      }

      dynamic "udp_options" {
        for_each = egress_security_rules.value.udp_min != null ? [1] : []
        content {
          min = egress_security_rules.value.udp_min
          max = egress_security_rules.value.udp_max
        }
      }
    }
  }

  freeform_tags = var.freeform_tags
  defined_tags  = var.defined_tags
}
