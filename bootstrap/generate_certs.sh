#!/usr/bin/env bash
# ---------------------------------------------------------------------------
#  Generate self-signed TLS certificates for every APTS component.
#
#  Produces, under ./certs/ :
#     <component>.key      — private key (600)
#     <component>.crt      — self-signed certificate (SAN=DNS:<component>)
#     trust-bundle.pem     — every .crt concatenated; every container mounts
#                            this as its trust store for outbound TLS
#
#  Certificates last 397 days (max any browser will accept, and also a
#  reasonable rotation cadence).
# ---------------------------------------------------------------------------
set -euo pipefail

CERT_DIR="${CERT_DIR:-./certs}"
DAYS="${CERT_DAYS:-397}"

# The container hostnames used on the APTS Docker network.  These MUST match
# the service names in docker-compose.yml — TLS clients verify SNI against
# them via the trust bundle.
COMPONENTS=(
    orchestrator
    agent-recon
    agent-vuln
    agent-mitre
    agent-exploit
    agent-script
    agent-adviser
    database
    sandbox
)

mkdir -p "$CERT_DIR"
umask 077

echo "==> generating certificates in $CERT_DIR/"
for name in "${COMPONENTS[@]}"; do
    key="$CERT_DIR/$name.key"
    crt="$CERT_DIR/$name.crt"

    if [[ -f "$key" && -f "$crt" ]]; then
        echo "    $name: already present, skipping"
        continue
    fi

    openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days "$DAYS" \
        -keyout "$key" -out "$crt" \
        -subj "/CN=$name" \
        -addext "subjectAltName=DNS:$name,DNS:localhost" \
        -addext "basicConstraints=CA:false" \
        -addext "keyUsage=digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth,clientAuth" \
        2>/dev/null

    chmod 600 "$key"
    chmod 644 "$crt"
    echo "    $name: generated"
done

echo "==> building trust bundle"
rm -f "$CERT_DIR/trust-bundle.pem"
for name in "${COMPONENTS[@]}"; do
    cat "$CERT_DIR/$name.crt" >> "$CERT_DIR/trust-bundle.pem"
done
chmod 644 "$CERT_DIR/trust-bundle.pem"

echo
echo "certs:        $(ls "$CERT_DIR" | wc -l) files"
echo "trust bundle: $CERT_DIR/trust-bundle.pem ($(wc -l < "$CERT_DIR/trust-bundle.pem") lines)"
echo "done."
