#!/usr/bin/env bash
# certbot --deploy-hook: runs only when a certificate was actually renewed.
#
#   sudo install -m 755 deploy/systemd/certbot-deploy-hook.sh \
#        /etc/letsencrypt/renewal-hooks/deploy/claude-cloak.sh
#
# uvicorn reads the certificate once at startup, so a renewal needs a restart.
# The port-80 listener serves the challenge from the webroot, so renewal
# itself causes no downtime — only this restart, which takes about a second.
set -euo pipefail
systemctl restart claude-cloak
logger -t claude-cloak "restarted after certificate renewal"
