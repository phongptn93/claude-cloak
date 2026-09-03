#!/usr/bin/env bash
# certbot deploy hook: publish the renewed certificate to the service and
# restart it. Runs only when a certificate actually changed.
#
#   sudo install -m 755 deploy/systemd/certbot-deploy-hook.sh \
#        /etc/letsencrypt/renewal-hooks/deploy/claude-cloak.sh
#
# The proxy reads its certificate from its own data directory rather than
# from /etc/letsencrypt. Granting the service user access to the letsencrypt
# tree instead looks simpler but breaks on the first renewal: certbot writes
# a NEW file into archive/ each time (privkey2.pem, privkey3.pem …), and a
# plain `setfacl -Rm` only covers the files that existed when it ran. The
# service then cannot read the new key and crash-loops — 60 days later, with
# nobody watching. Copying is explicit and has no inheritance to get wrong.
set -euo pipefail

DATA_DIR=/var/lib/claude-cloak
SERVICE_USER=claude-cloak
TLS_DIR="$DATA_DIR/tls"

# certbot exports RENEWED_LINEAGE for deploy hooks. Allow a manual run for
# the very first issue, when the hook has not been triggered yet.
LINEAGE="${RENEWED_LINEAGE:-${1:-}}"
if [ -z "$LINEAGE" ]; then
    LINEAGE=$(find /etc/letsencrypt/live -mindepth 1 -maxdepth 1 -type d | head -1)
fi
[ -n "$LINEAGE" ] && [ -f "$LINEAGE/privkey.pem" ] || {
    echo "no certificate lineage found (set RENEWED_LINEAGE or pass it as \$1)" >&2
    exit 1
}

install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 700 "$TLS_DIR"
install -o "$SERVICE_USER" -g "$SERVICE_USER" -m 644 "$LINEAGE/fullchain.pem" "$TLS_DIR/fullchain.pem"
install -o "$SERVICE_USER" -g "$SERVICE_USER" -m 600 "$LINEAGE/privkey.pem" "$TLS_DIR/privkey.pem"

# uvicorn reads the certificate once at startup, so a renewal only takes
# effect on restart. Renewal itself is downtime-free: the proxy serves the
# http-01 challenge from ACME_WEBROOT while it keeps running.
systemctl restart claude-cloak
logger -t claude-cloak "published renewed certificate from $LINEAGE and restarted"
