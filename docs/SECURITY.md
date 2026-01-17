# Null-Logs Security Notes

- Run the daemon as dedicated user `null-logs` with minimal capabilities (configure via systemd unit).
- Protect the HMAC key at `/etc/null-logs/key` with permissions 600 and avoid world-readable storage.
- Use an HSM or cloud KMS for production key management; the current HMAC key is stored in memory and wiped when closed.
- Rotate keys regularly and maintain log rotation and retention policies.
- Consider using SELinux/AppArmor policies to reduce damage from potential compromise.

For production: enable remote TLS-based ingestion and restrict access to logs via ACLs and centralized SIEM ingestion.