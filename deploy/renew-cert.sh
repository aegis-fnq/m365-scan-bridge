#!/bin/sh
# Reissue the bridge's TLS server certificate from the local CA when fewer than
# RENEW_DAYS (default 60) days remain, then restart the service. It does nothing
# while the certificate has time left, so it is safe to run often. Run as root,
# for example from m365-scan-bridge-renew-cert.timer.
#
# Environment: BRIDGE_DIR (default /etc/m365-scan-bridge), BRIDGE_SERVICE
# (default m365-scan-bridge), RENEW_DAYS (default 60).
set -eu

DIR=${BRIDGE_DIR:-/etc/m365-scan-bridge}
SERVICE=${BRIDGE_SERVICE:-m365-scan-bridge}
RENEW_DAYS=${RENEW_DAYS:-60}
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ -f "$DIR/tls-cert.pem" ] &&
    openssl x509 -in "$DIR/tls-cert.pem" -noout -checkend $((RENEW_DAYS * 86400)) >/dev/null; then
    echo "renew-cert.sh: certificate has more than $RENEW_DAYS days left; nothing to do"
    exit 0
fi

"$HERE/make-ca.sh" --server-only --dir "$DIR"
systemctl restart "$SERVICE"
echo "renew-cert.sh: certificate reissued and $SERVICE restarted"
