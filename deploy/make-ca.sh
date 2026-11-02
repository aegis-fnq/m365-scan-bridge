#!/bin/sh
# Create a small local certificate authority and issue the bridge's TLS server
# certificate from it. Import only ca-cert.pem into the printer.
#
# Usage:
#   make-ca.sh --ip 192.0.2.20 [--dns bridge.example.internal] [--dir DIR] [--owner USER]
#   make-ca.sh --server-only [--ip IP] [--dns NAME] [--dir DIR]
#       reissue the server certificate only; --ip/--dns replace the address(es) recorded
#       in DIR/cert.env (give both if both should stay), e.g. after the bridge moves
#
# DIR defaults to /etc/m365-scan-bridge; USER (owner of the server key) to m365-scan-bridge.
# Environment overrides: BRIDGE_DIR, BRIDGE_OWNER, CA_DAYS (default 3650), SERVER_DAYS (default 397).
#
# Every certificate's notBefore is backdated by 7 days: a printer whose clock is
# slightly behind would otherwise reject a certificate as "not valid yet".
set -eu

DIR=${BRIDGE_DIR:-/etc/m365-scan-bridge}
OWNER=${BRIDGE_OWNER:-m365-scan-bridge}
CA_DAYS=${CA_DAYS:-3650}
SERVER_DAYS=${SERVER_DAYS:-397}
IP=
DNS=
SERVER_ONLY=0
NEW_NAMES=0

die() { echo "make-ca.sh: $*" >&2; exit 1; }
# cert.env is sourced by root, and the values go into an openssl config, so only plain
# addresses and host names are accepted.
valid_ip() {
    case $1 in
        *[!0-9.]*) ;;
        *.*.*.*)
            oldifs=$IFS; IFS=.; set -- $1; IFS=$oldifs
            [ $# -eq 4 ] || return 1
            for o; do
                case $o in ''|*[!0-9]*|0?*) return 1 ;; esac
                [ "$o" -le 255 ] || return 1
            done
            return 0 ;;
        *) return 1 ;;
    esac
    case $1 in
        *:*:*) case $1 in *[!0-9A-Fa-f:.]*|*:::*) return 1 ;; *) return 0 ;; esac ;;
    esac
    return 1
}
valid_dns() {
    case $1 in
        ''|*[!A-Za-z0-9.-]*|.*|*..*|-*) return 1 ;;
    esac
    [ ${#1} -le 253 ]
}
check_names() {
    [ -z "$IP" ] || valid_ip "$IP" || die "--ip $IP is not an IPv4 or IPv6 address"
    [ -z "$DNS" ] || valid_dns "$DNS" || die "--dns $DNS is not a host name (letters, digits, hyphens and dots only)"
}
# Run openssl quietly, showing its output only if it fails.
quiet() { "$@" > "$WORK/out.log" 2>&1 || { cat "$WORK/out.log" >&2; die "failed: $1 $2"; }; }

while [ $# -gt 0 ]; do
    case $1 in
        --ip) IP=${2:?--ip needs a value}; NEW_NAMES=1; shift 2 ;;
        --dns) DNS=${2:?--dns needs a value}; NEW_NAMES=1; shift 2 ;;
        --dir) DIR=${2:?--dir needs a value}; shift 2 ;;
        --owner) OWNER=${2:?--owner needs a value}; shift 2 ;;
        --server-only) SERVER_ONLY=1; shift ;;
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

command -v openssl >/dev/null || die "openssl is not installed"
mkdir -p "$DIR"
umask 077

if [ "$SERVER_ONLY" = 1 ]; then
    [ -f "$DIR/ca-key.pem" ] || die "no CA in $DIR; run without --server-only first"
    if [ "$NEW_NAMES" = 0 ]; then
        [ -f "$DIR/cert.env" ] || die "$DIR/cert.env is missing; give --ip and/or --dns"
        # shellcheck disable=SC1091
        . "$DIR/cert.env"
    fi
    check_names
    [ -n "$IP$DNS" ] || die "no --ip or --dns to certify"
else
    check_names
    [ -n "$IP$DNS" ] || die "give --ip and/or --dns: the address the printer uses to reach the bridge"
    if [ -e "$DIR/ca-key.pem" ]; then
        [ -e "$DIR/tls-cert.pem" ] ||
            die "the CA already exists in $DIR but the server certificate does not; issue it with: make-ca.sh --server-only --ip ${IP:-ADDRESS}${DNS:+ --dns $DNS}"
        die "$DIR/ca-key.pem already exists; refusing to overwrite the CA (use --server-only to reissue the server certificate, adding --ip/--dns to change its address)"
    fi
fi

SAN=
[ -n "$IP" ] && SAN="IP:$IP"
[ -n "$DNS" ] && SAN="${SAN:+$SAN,}DNS:$DNS"
CN=${DNS:-$IP}

START=$(date -u -d '7 days ago' +%y%m%d%H%M%SZ 2>/dev/null) || die "needs GNU date (date -d)"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
mkdir "$WORK/new"
: > "$WORK/index.txt"
cat > "$WORK/ca.cnf" <<CNF
[ca]
default_ca = local
[local]
dir = $WORK
database = $WORK/index.txt
new_certs_dir = $WORK/new
rand_serial = yes
default_md = sha256
policy = anything
copy_extensions = none
unique_subject = no
[anything]
commonName = supplied
[ca_ext]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[server_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $SAN
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF

if [ "$SERVER_ONLY" = 0 ]; then
    # Built in the scratch directory and moved into place only once complete, so a failed
    # run leaves no half-made CA behind to block the next attempt.
    quiet openssl req -new -newkey rsa:3072 -nodes -subj "/CN=m365-scan-bridge local CA" \
        -keyout "$WORK/ca-key.pem" -out "$WORK/ca.csr"
    quiet openssl ca -batch -selfsign -config "$WORK/ca.cnf" -keyfile "$WORK/ca-key.pem" \
        -startdate "$START" -days "$CA_DAYS" -extensions ca_ext \
        -in "$WORK/ca.csr" -out "$WORK/ca-cert.pem" -notext
    chmod 600 "$WORK/ca-key.pem"
    chmod 644 "$WORK/ca-cert.pem"
    mv "$WORK/ca-cert.pem" "$DIR/ca-cert.pem"
    mv "$WORK/ca-key.pem" "$DIR/ca-key.pem"
fi

quiet openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$CN" \
    -keyout "$WORK/tls-key.pem" -out "$WORK/server.csr"
quiet openssl ca -batch -config "$WORK/ca.cnf" -cert "$DIR/ca-cert.pem" -keyfile "$DIR/ca-key.pem" \
    -startdate "$START" -days "$SERVER_DAYS" -extensions server_ext \
    -in "$WORK/server.csr" -out "$WORK/tls-cert.pem" -notext
openssl verify -CAfile "$DIR/ca-cert.pem" "$WORK/tls-cert.pem" >/dev/null || die "issued certificate does not verify"

# Move both halves into place together, so the service never sees a mismatched pair.
chmod 600 "$WORK/tls-key.pem"
chmod 644 "$WORK/tls-cert.pem"
if id "$OWNER" >/dev/null 2>&1; then
    chown "$OWNER:" "$WORK/tls-key.pem" "$WORK/tls-cert.pem"
else
    echo "make-ca.sh: user $OWNER does not exist; the server key stays owned by $(id -un)" >&2
fi
mv -f "$WORK/tls-key.pem" "$DIR/tls-key.pem"
mv -f "$WORK/tls-cert.pem" "$DIR/tls-cert.pem"
# Record the address(es) for renew-cert.sh, after a new CA or an explicit change.
if [ "$SERVER_ONLY" = 0 ] || [ "$NEW_NAMES" = 1 ]; then
    printf 'IP=%s\nDNS=%s\n' "$IP" "$DNS" > "$WORK/cert.env"
    chmod 644 "$WORK/cert.env"
    mv -f "$WORK/cert.env" "$DIR/cert.env"
fi

echo "server certificate for $SAN written to $DIR/tls-cert.pem (valid $SERVER_DAYS days)"
if [ "$SERVER_ONLY" = 0 ]; then
    echo "import $DIR/ca-cert.pem (and only that file) into the printer's trusted certificates"
fi
