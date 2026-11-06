# Test-only requirement: `mock_provider` needs Terraform >= 1.7 / OpenTofu >= 1.7.
# The module itself still supports >= 1.5, so required_version is deliberately
# not bumped for these tests.

mock_provider "oci" {}

variables {
  compartment_id = "ocid1.compartment.oc1..aaaaaaaaexample"
  vcn_id         = "ocid1.vcn.oc1.phx.aaaaaaaaexample"
  display_name   = "unit-test-sl"
}

run "defaults_create_no_ingress_and_allow_all_egress" {
  assert {
    condition     = length(oci_core_security_list.this.ingress_security_rules) == 0
    error_message = "Module must not create any ingress rule by default."
  }

  assert {
    condition     = length(oci_core_security_list.this.egress_security_rules) == 1
    error_message = "Default egress should be a single allow-all rule."
  }

  assert {
    condition = alltrue([
      for rule in oci_core_security_list.this.egress_security_rules :
      rule.protocol == "all" && rule.destination == "0.0.0.0/0" && rule.stateless == false
    ])
    error_message = "Default egress rule should be stateful protocol \"all\" to 0.0.0.0/0."
  }
}

run "rejects_world_open_ssh" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol = "6"
        source   = "0.0.0.0/0"
        tcp_min  = 22
        tcp_max  = 22
      }
    ]
  }

  expect_failures = [oci_core_security_list.this]
}

run "rejects_world_open_rdp_over_ipv6" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol = "6"
        source   = "::/0"
        tcp_min  = 3389
        tcp_max  = 3389
      }
    ]
  }

  expect_failures = [oci_core_security_list.this]
}

run "rejects_world_open_port_range_containing_a_database_port" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol = "6"
        source   = "0.0.0.0/0"
        tcp_min  = 5000
        tcp_max  = 6000 # spans 5432 (PostgreSQL) and 5900 (VNC)
      }
    ]
  }

  expect_failures = [oci_core_security_list.this]
}

run "rejects_world_open_protocol_all" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol = "all"
        source   = "0.0.0.0/0"
      }
    ]
  }

  expect_failures = [oci_core_security_list.this]
}

run "rejects_world_open_tcp_with_no_port_range" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol = "6"
        source   = "0.0.0.0/0"
      }
    ]
  }

  expect_failures = [oci_core_security_list.this]
}

run "allows_world_open_https" {
  variables {
    ingress_rules = [
      {
        protocol = "6"
        source   = "0.0.0.0/0"
        tcp_min  = 443
        tcp_max  = 443
      }
    ]
  }

  assert {
    condition     = length(oci_core_security_list.this.ingress_security_rules) == 1
    error_message = "Public HTTPS ingress must be allowed without an opt-in."
  }
}

run "guard_skips_icmp" {
  variables {
    ingress_rules = [
      {
        protocol    = "1"
        source      = "0.0.0.0/0"
        description = "Path MTU discovery"
      },
      {
        protocol = "58"
        source   = "::/0"
      }
    ]
  }

  assert {
    condition     = length(oci_core_security_list.this.ingress_security_rules) == 2
    error_message = "ICMP carries no ports, so the admin-port guard must not block it."
  }
}

run "guard_skips_non_public_admin_ports" {
  variables {
    ingress_rules = [
      {
        protocol = "6"
        source   = "10.0.0.0/16"
        tcp_min  = 22
        tcp_max  = 22
      }
    ]
  }

  assert {
    condition     = length(oci_core_security_list.this.ingress_security_rules) == 1
    error_message = "SSH from a private CIDR must be allowed."
  }
}

run "guard_skips_service_cidr_block_sources" {
  variables {
    ingress_rules = [
      {
        protocol    = "6"
        source      = "all-phx-services-in-oracle-services-network"
        source_type = "SERVICE_CIDR_BLOCK"
        tcp_min     = 22
        tcp_max     = 22
      }
    ]
  }

  assert {
    condition     = length(oci_core_security_list.this.ingress_security_rules) == 1
    error_message = "Oracle service CIDR labels are not public CIDRs and must pass the guard."
  }
}

run "opt_in_allows_world_open_ssh" {
  variables {
    allow_public_admin_ingress = true
    ingress_rules = [
      {
        protocol = "6"
        source   = "0.0.0.0/0"
        tcp_min  = 22
        tcp_max  = 22
      }
    ]
  }

  assert {
    condition     = length(oci_core_security_list.this.ingress_security_rules) == 1
    error_message = "allow_public_admin_ingress = true must permit world-open SSH."
  }
}

run "port_range_is_rendered_into_tcp_options" {
  variables {
    ingress_rules = [
      {
        protocol = "6"
        source   = "10.0.0.0/16"
        tcp_min  = 8080
        tcp_max  = 8090
      }
    ]
  }

  assert {
    condition = alltrue([
      for rule in oci_core_security_list.this.ingress_security_rules :
      length(rule.tcp_options) == 1 && rule.tcp_options[0].min == 8080 && rule.tcp_options[0].max == 8090
    ])
    error_message = "tcp_min/tcp_max must be rendered into a tcp_options block."
  }
}

run "rejects_invalid_protocol_name" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol = "tcp"
        source   = "10.0.0.0/16"
      }
    ]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_invalid_source_type" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol    = "6"
        source      = "10.0.0.0/16"
        source_type = "NETWORK_SECURITY_GROUP"
      }
    ]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_non_cidr_source" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol = "6"
        source   = "10.0.0.1"
        tcp_min  = 443
        tcp_max  = 443
      }
    ]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_half_specified_port_range" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol = "6"
        source   = "10.0.0.0/16"
        tcp_max  = 443
      }
    ]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_out_of_range_port" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol = "6"
        source   = "10.0.0.0/16"
        tcp_min  = 0
        tcp_max  = 65536
      }
    ]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_inverted_port_range" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol = "6"
        source   = "10.0.0.0/16"
        tcp_min  = 8080
        tcp_max  = 80
      }
    ]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_tcp_options_on_a_non_tcp_protocol" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol = "all"
        source   = "10.0.0.0/16"
        tcp_min  = 443
        tcp_max  = 443
      }
    ]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_invalid_egress_destination" {
  command = plan

  variables {
    egress_rules = [
      {
        protocol    = "all"
        destination = "not-a-cidr"
      }
    ]
  }

  expect_failures = [var.egress_rules]
}

run "rejects_half_specified_egress_port_range" {
  command = plan

  variables {
    egress_rules = [
      {
        protocol    = "6"
        destination = "10.0.0.0/16"
        udp_min     = 53
      }
    ]
  }

  expect_failures = [var.egress_rules]
}

run "stateless_rules_in_both_directions_pass_the_check" {
  variables {
    ingress_rules = [
      {
        protocol  = "6"
        source    = "10.0.0.0/16"
        stateless = true
        tcp_min   = 443
        tcp_max   = 443
      }
    ]
    egress_rules = [
      {
        protocol    = "all"
        destination = "10.0.0.0/16"
        stateless   = true
      }
    ]
  }

  assert {
    condition = alltrue([
      for rule in oci_core_security_list.this.ingress_security_rules : rule.stateless
    ])
    error_message = "stateless = true must be propagated to the ingress rule."
  }
}

# --- ICMP type/code ---------------------------------------------------------

run "icmp_type_and_code_are_rendered_into_icmp_options" {
  variables {
    ingress_rules = [
      {
        protocol  = "1"
        source    = "0.0.0.0/0"
        icmp_type = 3
        icmp_code = 4
      }
    ]
  }

  assert {
    condition = alltrue([
      for rule in oci_core_security_list.this.ingress_security_rules :
      length(rule.icmp_options) == 1 && rule.icmp_options[0].type == 3 && rule.icmp_options[0].code == 4
    ])
    error_message = "icmp_type/icmp_code must be rendered into an icmp_options block."
  }
}

run "icmp_type_without_code_matches_every_code" {
  variables {
    ingress_rules = [
      {
        protocol  = "58"
        source    = "::/0"
        icmp_type = 2
      }
    ]
  }

  assert {
    condition = alltrue([
      for rule in oci_core_security_list.this.ingress_security_rules :
      length(rule.icmp_options) == 1 && rule.icmp_options[0].type == 2 && rule.icmp_options[0].code == null
    ])
    error_message = "An ICMPv6 rule with only icmp_type must render icmp_options with that type and no code."
  }
}

run "icmp_without_type_renders_no_icmp_options" {
  variables {
    ingress_rules = [
      {
        protocol = "1"
        source   = "10.0.0.0/16"
      }
    ]
  }

  assert {
    condition = alltrue([
      for rule in oci_core_security_list.this.ingress_security_rules : length(rule.icmp_options) == 0
    ])
    error_message = "Without icmp_type the rule must keep allowing every ICMP type (no icmp_options block)."
  }
}

run "egress_icmp_type_is_rendered" {
  variables {
    egress_rules = [
      {
        protocol    = "1"
        destination = "0.0.0.0/0"
        icmp_type   = 8
      }
    ]
  }

  assert {
    condition = alltrue([
      for rule in oci_core_security_list.this.egress_security_rules :
      length(rule.icmp_options) == 1 && rule.icmp_options[0].type == 8
    ])
    error_message = "icmp_type must be rendered into egress icmp_options as well."
  }
}

run "rejects_icmp_options_on_tcp" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol  = "6"
        source    = "10.0.0.0/16"
        icmp_type = 3
      }
    ]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_icmp_code_without_type" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol  = "1"
        source    = "10.0.0.0/16"
        icmp_code = 4
      }
    ]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_out_of_range_icmp_type" {
  command = plan

  variables {
    ingress_rules = [
      {
        protocol  = "1"
        source    = "10.0.0.0/16"
        icmp_type = 256
      }
    ]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_fractional_icmp_code" {
  command = plan

  variables {
    egress_rules = [
      {
        protocol    = "58"
        destination = "::/0"
        icmp_type   = 1
        icmp_code   = 0.5
      }
    ]
  }

  expect_failures = [var.egress_rules]
}

run "rejects_icmp_options_on_protocol_all_egress" {
  command = plan

  variables {
    egress_rules = [
      {
        protocol    = "all"
        destination = "0.0.0.0/0"
        icmp_type   = 3
      }
    ]
  }

  expect_failures = [var.egress_rules]
}
