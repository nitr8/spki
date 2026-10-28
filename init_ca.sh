#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$BASE_DIR/pki.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[ERROR] Missing $ENV_FILE"
  exit 1
fi

# shellcheck source=/dev/null
source "$ENV_FILE"

umask 077

ROOT_DIR="$BASE_DIR/ca/root"
INT_DIR="$BASE_DIR/ca/intermediate"
ROOT_KEY="$ROOT_DIR/private/root-ca.key.pem"
ROOT_CERT="$ROOT_DIR/certs/root-ca.cert.pem"
ROOT_CNF="$ROOT_DIR/root-ca.openssl.cnf"
ROOT_SERIAL="$ROOT_DIR/certs/root-ca.cert.srl"

INT_KEY="$INT_DIR/private/intermediate-ca.key.pem"
INT_CSR="$INT_DIR/csr/intermediate-ca.csr.pem"
INT_CERT="$INT_DIR/certs/intermediate-ca.cert.pem"
INT_CNF="$INT_DIR/intermediate-ca.openssl.cnf"
INT_SERIAL="$INT_DIR/certs/intermediate-ca.cert.srl"
CHAIN_CERT="$INT_DIR/certs/ca-chain.cert.pem"

mkdir -p "$ROOT_DIR/private" "$ROOT_DIR/certs" "$ROOT_DIR/csr" \
         "$INT_DIR/private" "$INT_DIR/certs" "$INT_DIR/csr" "$BASE_DIR/issued"

need_openssl() {
  if ! command -v openssl >/dev/null 2>&1; then
    echo "[ERROR] openssl not found. Install OpenSSL first."
    exit 1
  fi
}

render_template() {
  local template="$1"
  local output="$2"
  awk \
    -v ROOT_KEY_BITS="$ROOT_KEY_BITS" \
    -v INTERMEDIATE_KEY_BITS="$INTERMEDIATE_KEY_BITS" \
    -v COUNTRY="$COUNTRY" \
    -v STATE="$STATE" \
    -v LOCALITY="$LOCALITY" \
    -v ORG="$ORG" \
    -v ORG_UNIT="$ORG_UNIT" \
    -v ROOT_CA_CN="$ROOT_CA_CN" \
    -v INTERMEDIATE_CA_CN="$INTERMEDIATE_CA_CN" '
      {
        gsub(/\{\{ROOT_KEY_BITS\}\}/, ROOT_KEY_BITS)
        gsub(/\{\{INTERMEDIATE_KEY_BITS\}\}/, INTERMEDIATE_KEY_BITS)
        gsub(/\{\{COUNTRY\}\}/, COUNTRY)
        gsub(/\{\{STATE\}\}/, STATE)
        gsub(/\{\{LOCALITY\}\}/, LOCALITY)
        gsub(/\{\{ORG\}\}/, ORG)
        gsub(/\{\{ORG_UNIT\}\}/, ORG_UNIT)
        gsub(/\{\{ROOT_CA_CN\}\}/, ROOT_CA_CN)
        gsub(/\{\{INTERMEDIATE_CA_CN\}\}/, INTERMEDIATE_CA_CN)
        print
      }
    ' "$template" > "$output"
}

need_openssl

if [[ -f "$ROOT_KEY" || -f "$ROOT_CERT" ]]; then
  echo "[INFO] Root CA already exists:"
  echo "       $ROOT_CERT"
else
  echo "[INFO] Creating Root CA..."
  render_template "$BASE_DIR/templates/root.cnf.tpl" "$ROOT_CNF"
  openssl genrsa -out "$ROOT_KEY" "$ROOT_KEY_BITS"
  chmod 600 "$ROOT_KEY"
  openssl req -x509 -new -key "$ROOT_KEY" \
    -sha256 -days "$ROOT_DAYS" \
    -out "$ROOT_CERT" \
    -config "$ROOT_CNF" \
    -extensions v3_root_ca
  chmod 644 "$ROOT_CERT"
  echo "[OK] Root CA created: $ROOT_CERT"
fi

if [[ -f "$INT_KEY" || -f "$INT_CERT" ]]; then
  echo "[INFO] Intermediate CA already exists:"
  echo "       $INT_CERT"
else
  echo "[INFO] Creating Intermediate CA..."
  render_template "$BASE_DIR/templates/intermediate.cnf.tpl" "$INT_CNF"
  openssl genrsa -out "$INT_KEY" "$INTERMEDIATE_KEY_BITS"
  chmod 600 "$INT_KEY"
  openssl req -new -key "$INT_KEY" \
    -out "$INT_CSR" \
    -config "$INT_CNF"
  openssl x509 -req \
    -in "$INT_CSR" \
    -CA "$ROOT_CERT" \
    -CAkey "$ROOT_KEY" \
    -CAcreateserial \
    -out "$INT_CERT" \
    -days "$INTERMEDIATE_DAYS" \
    -sha256 \
    -extfile "$INT_CNF" \
    -extensions v3_intermediate_ca
  chmod 644 "$INT_CERT"
  echo "[OK] Intermediate CA created: $INT_CERT"
fi

cat "$INT_CERT" "$ROOT_CERT" > "$CHAIN_CERT"
chmod 644 "$CHAIN_CERT"

openssl verify -CAfile "$ROOT_CERT" "$INT_CERT" >/dev/null

echo ""
echo "[OK] PKI ready."
echo ""
echo "Trust this file on your clients/devices:"
echo "  $ROOT_CERT"
echo ""
echo "Daily signing will use:"
echo "  $INT_CERT"
echo ""
echo "Generate a device cert with:"
echo "  ./cert_gen.sh nas"
echo "  ./cert_gen.sh nas --ip 192.168.1.10"
echo "  ./cert_gen.sh nas --ip 192.168.1.10 --force"
