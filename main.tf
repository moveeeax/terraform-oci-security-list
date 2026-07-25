locals {
  # CIDRs that mean "the entire internet".
  public_cidrs = ["0.0.0.0/0", "::/0"]

  # Protocols that carry no port numbers, so the port-exposure guard cannot and
  # should not apply to them. OCI uses IANA protocol numbers as strings.
  portless_protocols = ["1", "58"] # ICMP, ICMPv6

  # Ports that should never be reachable from the whole internet without the
  # operator saying so explicitly.
  admin_ports = [
    22,   # SSH
    23,   # Telnet
    3389, # RDP
    5900, # VNC
    5985, # WinRM (HTTP)
    5986, # WinRM (HTTPS)
  ]

  database_ports = [
    1433,  # MSSQL
    1521,  # Oracle DB
    1522,  # Oracle DB
    2181,  # ZooKeeper
    2379,  # etcd
    2380,  # etcd
    3306,  # MySQL / MariaDB
    5432,  # PostgreSQL
    5984,  # CouchDB
    6379,  # Redis
    7199,  # Cassandra JMX
    9042,  # Cassandra CQL
    9200,  # Elasticsearch / OpenSearch HTTP
    9300,  # Elasticsearch transport
    11211, # Memcached
    27017, # MongoDB
    27018, # MongoDB
    27019, # MongoDB
  ]

  protected_ports = concat(local.admin_ports, local.database_ports)

  # Ingress rules whose source is the entire internet. SERVICE_CIDR_BLOCK
  # sources are Oracle service labels, not CIDRs, so they are never public.
  public_ingress_rules = [
    for rule in var.ingress_rules : rule
    if rule.source_type == "CIDR_BLOCK" && contains(local.public_cidrs, rule.source)
  ]

  # Of those, the ones that actually reach a protected port -- either because
  # the rule covers every port of a port-based protocol, or because its
  # explicit range contains one.
  public_protected_ingress_rules = [
    for rule in local.public_ingress_rules : rule
    if !contains(local.portless_protocols, rule.protocol) && (
      rule.protocol == "all" ||
      (rule.protocol == "6" && rule.tcp_min == null) ||
      (rule.protocol == "17" && rule.udp_min == null) ||
      length([
        for port in local.protected_ports : port
        if(rule.tcp_min != null && port >= rule.tcp_min && port <= rule.tcp_max) ||
        (rule.udp_min != null && port >= rule.udp_min && port <= rule.udp_max)
      ]) > 0
    )
  ]

  stateless_ingress_count = length([for rule in var.ingress_rules : rule if rule.stateless])
  stateless_egress_count  = length([for rule in var.egress_rules : rule if rule.stateless])
}

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
        for_each = ingress_security_rules.value.tcp_min != null || ingress_security_rules.value.tcp_max != null ? [1] : []
        content {
          min = ingress_security_rules.value.tcp_min
          max = ingress_security_rules.value.tcp_max
        }
      }

      dynamic "udp_options" {
        for_each = ingress_security_rules.value.udp_min != null || ingress_security_rules.value.udp_max != null ? [1] : []
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
        for_each = egress_security_rules.value.tcp_min != null || egress_security_rules.value.tcp_max != null ? [1] : []
        content {
          min = egress_security_rules.value.tcp_min
          max = egress_security_rules.value.tcp_max
        }
      }

      dynamic "udp_options" {
        for_each = egress_security_rules.value.udp_min != null || egress_security_rules.value.udp_max != null ? [1] : []
        content {
          min = egress_security_rules.value.udp_min
          max = egress_security_rules.value.udp_max
        }
      }
    }
  }

  freeform_tags = var.freeform_tags
  defined_tags  = var.defined_tags

  lifecycle {
    precondition {
      condition = var.allow_public_admin_ingress || length(local.public_protected_ingress_rules) == 0
      error_message = join("\n", concat(
        ["These ingress rules expose administrative or database ports to the entire internet:"],
        [
          for rule in local.public_protected_ingress_rules :
          format(
            "  - protocol %s from %s%s%s",
            rule.protocol,
            rule.source,
            rule.tcp_min != null ? format(", tcp %d-%d", rule.tcp_min, rule.tcp_max) : "",
            rule.udp_min != null ? format(", udp %d-%d", rule.udp_min, rule.udp_max) : "",
          )
        ],
        ["Narrow the source CIDR, or set allow_public_admin_ingress = true to accept this exposure deliberately."]
      ))
    }
  }
}

# OCI stateless rules are not connection-tracked, so return traffic is only
# allowed if a rule in the opposite direction permits it. A stateless rule in
# one direction with nothing stateless in the other is almost always a
# misconfiguration that silently blackholes replies.
check "stateless_rules_have_a_return_path" {
  assert {
    condition     = local.stateless_ingress_count == 0 || local.stateless_egress_count > 0
    error_message = "Stateless ingress rules are defined but no egress rule is stateless. Stateless traffic is not connection-tracked, so replies need a matching stateless egress rule or they will be dropped."
  }

  assert {
    condition     = local.stateless_egress_count == 0 || local.stateless_ingress_count > 0
    error_message = "Stateless egress rules are defined but no ingress rule is stateless. Stateless traffic is not connection-tracked, so replies need a matching stateless ingress rule or they will be dropped."
  }
}
