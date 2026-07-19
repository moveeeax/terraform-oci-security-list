# terraform-oci-security-list

Terraform module that manages an [Oracle Cloud Infrastructure](https://www.oracle.com/cloud/)
security list within an existing VCN. Ingress and egress rules are supplied as typed
lists with optional TCP/UDP port ranges and stateless flags. By default it allows all
outbound traffic and no inbound traffic.

## Usage

```hcl
module "security_list" {
  source = "github.com/moveeeax/terraform-oci-security-list"

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
    }
  ]

  freeform_tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

A runnable example lives in [`examples/basic`](examples/basic).

## Requirements

| Name      | Version  |
|-----------|----------|
| terraform | >= 1.5   |
| oci       | >= 5.0   |

## Inputs

| Name             | Description                                                     | Type                | Default          | Required |
|------------------|-----------------------------------------------------------------|---------------------|------------------|:--------:|
| `compartment_id` | OCID of the compartment in which to create the security list.   | `string`            | n/a              |   yes    |
| `vcn_id`         | OCID of the VCN the security list belongs to.                   | `string`            | n/a              |   yes    |
| `display_name`   | Human-readable name for the security list.                      | `string`            | n/a              |   yes    |
| `ingress_rules`  | List of ingress rules with optional TCP/UDP port ranges.        | `list(object(...))` | `[]`             |    no    |
| `egress_rules`   | List of egress rules with optional TCP/UDP port ranges.         | `list(object(...))` | allow-all egress |    no    |
| `freeform_tags`  | Free-form tags applied to the security list.                    | `map(string)`       | `{}`             |    no    |
| `defined_tags`   | Defined tags applied to the security list, keyed `namespace.key`| `map(string)`       | `{}`             |    no    |

## Outputs

| Name           | Description                             |
|----------------|-----------------------------------------|
| `id`           | OCID of the security list.              |
| `display_name` | Display name of the security list.      |
| `state`        | Lifecycle state of the security list.   |

## License

[MIT](LICENSE)
