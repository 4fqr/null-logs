# Null-Logs Deployment Notes

1. Create system user/group:

   sudo useradd --system --no-create-home --shell /usr/sbin/nologin null-logs
   sudo mkdir -p /var/log/null-logs && sudo chown null-logs:null-logs /var/log/null-logs

2. Install and enable:

   sudo make install
   sudo systemctl daemon-reload
   sudo systemctl enable --now null-logs.service

3. Configure: edit `/etc/null-logs/null-logs.conf` (see defaults in `src/config.c`).

4. Rotate: `logrotate` config installed at `/etc/logrotate.d/null-logs` will HUP the service after rotation.
