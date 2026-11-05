# terraform-oci-security-list

Terraform module that manages an [Oracle Cloud Infrastructure](https://www.oracle.com/cloud/)
security list within an existing VCN. Ingress and egress rules are supplied as typed
lists with optional TCP/UDP port ranges and stateless flags. By default it allows all
outbound traffic and no inbound traffic.

Rules are validated at plan time: protocol numbers, source/destination types, CIDR
syntax and port ranges are all checked, and the module refuses to plan an ingress
rule that exposes an administrative or database port to the whole internet unless
you opt in explicitly.

## Usage

```hcl
module "security_list" {
  source = "github.com/moveeeax/terraform-oci-security-list?ref=v1.0.0"

  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = "prod-web-sl"

  ingress_rules = [
    {
      protocol    = "6"
      source      = "0.0.0.0/0"
      tcp_min     = 443
      tcp_max     = 443
      description = "Allow HTTPS"
    },
    {
      protocol    = "6"
      source      = "10.0.0.0/16"
      tcp_min     = 22
      tcp_max     = 22
      description = "Allow SSH from the admin network"
    }
  ]

  freeform_tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

A runnable example lives in [`examples/basic`](examples/basic).

## Rule schema

Both `ingress_rules` and `egress_rules` take a list of objects. Ingress rules use
`source`/`source_type`; egress rules use `destination`/`destination_type`.

| Field                            | Type     | Default        | Notes                                                                       |
|----------------------------------|----------|----------------|-----------------------------------------------------------------------------|
| `protocol`                       | `string` | required       | IANA protocol number as a **string** — `"1"` ICMP, `"6"` TCP, `"17"` UDP, `"58"` ICMPv6 — or `"all"` |
| `source` / `destination`         | `string` | required       | CIDR block, or an Oracle service label when the matching `*_type` is `SERVICE_CIDR_BLOCK` |
| `source_type` / `destination_type` | `string` | `CIDR_BLOCK` | `CIDR_BLOCK` or `SERVICE_CIDR_BLOCK`                                        |
| `stateless`                      | `bool`   | `false`        | See [stateless rules](#stateless-rules)                                     |
| `description`                    | `string` | `null`         | Free text shown in the console                                              |
| `tcp_min` / `tcp_max`            | `number` | `null`         | Destination port range; requires `protocol = "6"`. Omit both to allow every TCP port |
| `udp_min` / `udp_max`            | `number` | `null`         | Destination port range; requires `protocol = "17"`. Omit both to allow every UDP port |

Port ranges must be given as a pair. `tcp_max` without `tcp_min` (or vice versa) is
rejected rather than silently dropped, because a dropped range would leave the rule
open on every port of that protocol.

## Public exposure guard

`allow_public_admin_ingress` defaults to `false`. With that default, `terraform plan`
fails if any ingress rule sourced from `0.0.0.0/0` or `::/0` can reach one of these
ports — either through an explicit range that contains it, through `protocol = "all"`,
or through a TCP/UDP rule with no port range at all:

- **Administrative:** 22 (SSH), 23 (Telnet), 3389 (RDP), 5900 (VNC), 5985/5986 (WinRM)
- **Database and datastore:** 1433, 1521, 1522, 2181, 2379, 2380, 3306, 5432, 5984,
  6379, 7199, 9042, 9200, 9300, 11211, 27017, 27018, 27019

ICMP (`"1"`) and ICMPv6 (`"58"`) carry no port numbers and are never blocked by the
guard, and `SERVICE_CIDR_BLOCK` sources are not public CIDRs so they pass too. If the
exposure is intentional, set `allow_public_admin_ingress = true`.

## Stateless rules

OCI stateless rules are not connection-tracked, so return traffic is only permitted
if a rule in the opposite direction allows it. The module raises a plan-time warning
(a `check` block, so it never blocks an apply) when stateless rules exist in one
direction but not the other — a common way to silently blackhole replies, especially
since the default egress rule is *stateful*.

## Requirements

| Name      | Version  |
|-----------|----------|
| terraform | >= 1.5   |
| oci       | >= 5.0   |

The test suite under `tests/` additionally needs Terraform/OpenTofu >= 1.7 for
`mock_provider`; the module itself still supports 1.5.

## Inputs

| Name                         | Description                                                       | Type                | Default          | Required |
|------------------------------|-------------------------------------------------------------------|---------------------|------------------|:--------:|
| `compartment_id`             | OCID of the compartment in which to create the security list.     | `string`            | n/a              |   yes    |
| `vcn_id`                     | OCID of the VCN the security list belongs to.                     | `string`            | n/a              |   yes    |
| `display_name`               | Human-readable name for the security list.                        | `string`            | n/a              |   yes    |
| `ingress_rules`              | List of ingress rules with optional TCP/UDP port ranges.          | `list(object(...))` | `[]`             |    no    |
| `egress_rules`               | List of egress rules with optional TCP/UDP port ranges.           | `list(object(...))` | allow-all egress |    no    |
| `allow_public_admin_ingress` | Permit admin/database ports to be reachable from `0.0.0.0/0`.     | `bool`              | `false`          |    no    |
| `freeform_tags`              | Free-form tags applied to the security list.                      | `map(string)`       | `{}`             |    no    |
| `defined_tags`               | Defined tags applied to the security list, keyed `namespace.key`. | `map(string)`       | `{}`             |    no    |

## Outputs

| Name           | Description                             |
|----------------|-----------------------------------------|
| `id`           | OCID of the security list.              |
| `display_name` | Display name of the security list.      |
| `state`        | Lifecycle state of the security list.   |

## Development

```sh
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
terraform test          # runs tests/ against a mocked oci provider, no credentials needed
```

## License

[MIT](LICENSE)
