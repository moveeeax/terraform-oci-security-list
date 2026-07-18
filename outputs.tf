output "id" {
  description = "OCID of the security list."
  value       = oci_core_security_list.this.id
}

output "display_name" {
  description = "Display name of the security list."
  value       = oci_core_security_list.this.display_name
}

output "state" {
  description = "Lifecycle state of the security list."
  value       = oci_core_security_list.this.state
}
