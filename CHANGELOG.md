# Changelog

All notable changes to this module are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `icmp_type` and `icmp_code` on `ingress_rules` and `egress_rules`, rendered into
  `icmp_options`, so an ICMP or ICMPv6 rule can be narrowed to one message type
  (for example type 3 code 4 for path MTU discovery) instead of admitting every
  ICMP message. Both are optional; rules without them behave as before. Plan-time
  validation rejects them on protocols other than `"1"`/`"58"`, a code without a
  type, and values outside 0-255. The basic example ships a
  `icmp_path_mtu_discovery` preset.

### Changed

- CI: bump actions to their current majors, pin tool versions, and restrict the
  workflow token to `contents: read`.
- CI: add Dependabot for GitHub Actions and the Terraform provider.
- Docs: pin the README usage `source` to a release tag; fix the LICENSE year.

## [1.0.0]

Initial release (`v0.1.0` points at the same commit).

[Unreleased]: https://github.com/moveeeax/terraform-oci-security-list/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/moveeeax/terraform-oci-security-list/releases/tag/v1.0.0
