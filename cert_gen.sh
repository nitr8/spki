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

usage() {
  cat <<USAGE
Usage:
  ./cert_gen.sh HOSTNAME [IP]
  ./cert_gen.sh HOSTNAME --ip IP
  ./cert_gen.sh HOSTNAME --ip IP --force
  ./cert_gen.sh HOSTNAME --force --regen-config --regen-key

Examples:
  ./cert_gen.sh nas
  ./cert_gen.sh nas 192.168.1.10
  ./cert_gen.sh nas --ip 192.168.1.10
  ./cert_gen.sh router --domain acme.test --ip 192.168.1.1
  ./cert_gen.sh xclarity --ip 192.168.1.20 --dns xclarity.lan --force

Options:
  --ip IP          Add IP address SAN. If omitted, DEFAULT_IP from pki.env is used.
                   Can be repeated. The first IP becomes the primary IP.
  --dns NAME       Add extra DNS SAN. Can be repeated.
  --domain DOMAIN  Override DEFAULT_DOMAIN from pki.env.
  --days DAYS      Override SERVER_DAYS from pki.env.
  --editor CMD     Override EDITOR_CMD from pki.env.
  --force          Do not open editor and overwrite existing certificate output files.
                   Existing config/key are reused if present.
  --regen-config   Regenerate the OpenSSL config from the template, even if it exists.
  --regen-key      Generate a new private key, even if one already exists.
  --no-edit        Do not open editor, but do not imply overwrite.
  -h, --help       Show this help.
USAGE
}

need_openssl() {
  if ! command -v openssl >/dev/null 2>&1; then
    echo "[ERROR] openssl not found. Install OpenSSL first."
    exit 1
  fi
}

is_ip() {
  case "$1" in
    *.*.*.*) return 0 ;;
    *) return 1 ;;
  esac
}

clean_name() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g'
}

HOST=""
DOMAIN="$DEFAULT_DOMAIN"
PRIMARY_IP="$DEFAULT_IP"
PRIMARY_IP_SET="false"
DAYS="$SERVER_DAYS"
EDITOR_TO_USE="$EDITOR_CMD"
FORCE="false"
NO_EDIT="false"
REGEN_CONFIG="false"
REGEN_KEY="false"

# Do not use Bash arrays here. macOS still ships Bash 3.2 and `set -u`
# can be awkward with empty arrays. Newline lists are boring but robust.
EXTRA_DNS_LIST=""
EXTRA_IP_LIST=""

append_dns() {
  EXTRA_DNS_LIST="${EXTRA_DNS_LIST}${1}"$'\n'
}

append_ip() {
  EXTRA_IP_LIST="${EXTRA_IP_LIST}${1}"$'\n'
}

set_or_append_ip() {
  if [[ "$PRIMARY_IP_SET" == "false" ]]; then
    PRIMARY_IP="$1"
    PRIMARY_IP_SET="true"
  else
    append_ip "$1"
  fi
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --ip)
      shift
      if [[ $# -eq 0 ]]; then echo "[ERROR] --ip requires a value"; exit 1; fi
      set_or_append_ip "$1"
      ;;
    --dns)
      shift
      if [[ $# -eq 0 ]]; then echo "[ERROR] --dns requires a value"; exit 1; fi
      append_dns "$1"
      ;;
    --domain)
      shift
      if [[ $# -eq 0 ]]; then echo "[ERROR] --domain requires a value"; exit 1; fi
      DOMAIN="$1"
      ;;
    --days)
      shift
      if [[ $# -eq 0 ]]; then echo "[ERROR] --days requires a value"; exit 1; fi
      DAYS="$1"
      ;;
    --editor)
      shift
      if [[ $# -eq 0 ]]; then echo "[ERROR] --editor requires a value"; exit 1; fi
      EDITOR_TO_USE="$1"
      ;;
    --force)
      FORCE="true"
      NO_EDIT="true"
      ;;
    --regen-config)
      REGEN_CONFIG="true"
      ;;
    --regen-key)
      REGEN_KEY="true"
      ;;
    --no-edit)
      NO_EDIT="true"
      ;;
    --*)
      echo "[ERROR] Unknown option: $1"
      usage
      exit 1
      ;;
    *)
      if [[ -z "$HOST" ]]; then
        HOST="$1"
      elif is_ip "$1"; then
        set_or_append_ip "$1"
      else
        append_dns "$1"
      fi
      ;;
  esac
  shift
done

if [[ -z "$HOST" ]]; then
  echo "[ERROR] HOSTNAME is required."
  usage
  exit 1
fi

need_openssl

ROOT_CERT="$BASE_DIR/ca/root/certs/root-ca.cert.pem"
INT_CERT="$BASE_DIR/ca/intermediate/certs/intermediate-ca.cert.pem"
INT_KEY="$BASE_DIR/ca/intermediate/private/intermediate-ca.key.pem"

if [[ ! -f "$ROOT_CERT" || ! -f "$INT_CERT" || ! -f "$INT_KEY" ]]; then
  echo "[ERROR] CA is not initialized yet. Run: ./init_ca.sh"
  exit 1
fi

HOST="$(clean_name "$HOST")"
DOMAIN="$(clean_name "$DOMAIN")"

if [[ "$HOST" == *.* ]]; then
  FQDN="$HOST"
  SHORT_HOST="${HOST%%.*}"
else
  SHORT_HOST="$HOST"
  FQDN="$HOST.$DOMAIN"
fi

OUT_DIR="$BASE_DIR/issued/$FQDN"
CNF="$OUT_DIR/$FQDN.openssl.cnf"
KEY="$OUT_DIR/$FQDN.key.pem"
CSR="$OUT_DIR/$FQDN.csr.pem"
CERT="$OUT_DIR/$FQDN.cert.pem"
FULLCHAIN="$OUT_DIR/$FQDN.fullchain.pem"
CHAIN="$OUT_DIR/$FQDN.chain.pem"
TEXT="$OUT_DIR/$FQDN.cert.txt"

echo "[INFO] Target FQDN: $FQDN"
echo "[INFO] Output directory: $OUT_DIR"

if [[ -d "$OUT_DIR" && "$FORCE" != "true" ]]; then
  if [[ -f "$CERT" || -f "$FULLCHAIN" ]]; then
    echo "[ERROR] Output already exists: $OUT_DIR"
    echo "        Use --force to renew/overwrite certificate output files."
    echo "        Existing config/key will be reused if present."
    echo "        Example: ./cert_gen.sh $HOST --ip $PRIMARY_IP --force"
    echo "        To regenerate config/key too: add --regen-config and/or --regen-key"
    exit 1
  else
    echo "[WARN] Incomplete output folder exists, probably from a failed previous run: $OUT_DIR"
    echo "       Reusing existing config/key if present and continuing."
  fi
fi

if [[ "$FORCE" == "true" && -d "$OUT_DIR" ]]; then
  echo "[INFO] Renewal mode: existing output folder found."
  echo "[INFO] --force will overwrite certificate output files only."
  echo "[INFO] Existing config/key are reused unless --regen-config and/or --regen-key are supplied."
fi

mkdir -p "$OUT_DIR"

ALT_NAMES=""
DNS_N=1
IP_N=1

add_dns() {
  local name
  name="$(clean_name "$1")"
  if [[ -n "$name" ]]; then
    ALT_NAMES+="DNS.$DNS_N = $name"$'\n'
    DNS_N=$((DNS_N + 1))
  fi
}

add_ip() {
  local ip="$1"
  if [[ -n "$ip" ]]; then
    ALT_NAMES+="IP.$IP_N = $ip"$'\n'
    IP_N=$((IP_N + 1))
  fi
}

render_server_template() {
  local template="$1"
  local output="$2"
  local line

  : > "$output"

  # Use pure Bash line rendering rather than awk -v with multiline values.
  # macOS awk can fail with: "awk: newline in string DNS.1 = ...".
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == *"{{ALT_NAMES}}"* ]]; then
      printf '%s' "$ALT_NAMES" >> "$output"
      continue
    fi

    line="${line//\{\{SERVER_KEY_BITS\}\}/$SERVER_KEY_BITS}"
    line="${line//\{\{COUNTRY\}\}/$COUNTRY}"
    line="${line//\{\{STATE\}\}/$STATE}"
    line="${line//\{\{LOCALITY\}\}/$LOCALITY}"
    line="${line//\{\{ORG\}\}/$ORG}"
    line="${line//\{\{ORG_UNIT\}\}/$ORG_UNIT}"
    line="${line//\{\{FQDN\}\}/$FQDN}"

    printf '%s\n' "$line" >> "$output"
  done < "$template"
}

add_dns "$FQDN"
if [[ "$SHORT_HOST" != "$FQDN" ]]; then
  add_dns "$SHORT_HOST"
fi

while IFS= read -r dns; do
  [[ -n "$dns" ]] && add_dns "$dns"
done <<< "$EXTRA_DNS_LIST"

add_ip "$PRIMARY_IP"
while IFS= read -r ip; do
  [[ -n "$ip" ]] && add_ip "$ip"
done <<< "$EXTRA_IP_LIST"

if [[ -f "$CNF" && "$REGEN_CONFIG" != "true" ]]; then
  echo "[INFO] Config: reusing existing OpenSSL config."
  echo "[INFO] Config path: $CNF"
  if [[ "$FORCE" == "true" ]]; then
    echo "[INFO] Config: --force preserves the existing config for safe renewals."
  fi
  if [[ -n "$EXTRA_DNS_LIST" || -n "$EXTRA_IP_LIST" || "$PRIMARY_IP_SET" == "true" ]]; then
    echo "[WARN] SAN arguments were supplied, but the existing config is being reused."
    echo "[WARN] Edit the config when it opens, or use --regen-config to rebuild it from arguments."
  fi
else
  if [[ -f "$CNF" && "$REGEN_CONFIG" == "true" ]]; then
    CONFIG_BACKUP="$CNF.backup-$(date +%Y%m%d-%H%M%S)"
    cp "$CNF" "$CONFIG_BACKUP"
    echo "[INFO] Config: existing OpenSSL config backed up: $CONFIG_BACKUP"
  fi
  echo "[INFO] Config: rendering OpenSSL config from template."
  echo "[INFO] Config path: $CNF"
  render_server_template "$BASE_DIR/templates/server.cnf.tpl" "$CNF"
fi

if [[ "$NO_EDIT" != "true" ]]; then
  echo "[INFO] Editor: opening OpenSSL config in: $EDITOR_TO_USE"
  echo "[INFO] Editor: save and quit to continue certificate generation."
  "$EDITOR_TO_USE" "$CNF"
else
  echo "[INFO] Editor: non-interactive mode, using OpenSSL config as-is."
fi

if [[ -f "$KEY" && "$REGEN_KEY" != "true" ]]; then
  echo "[INFO] Key: reusing existing private key."
  echo "[INFO] Key path: $KEY"
  if [[ "$FORCE" == "true" ]]; then
    echo "[INFO] Key: --force preserves the existing key for safe renewals."
  fi
  echo "[INFO] Key: use --regen-key if you intentionally want a new private key."
else
  if [[ -f "$KEY" && "$REGEN_KEY" == "true" ]]; then
    KEY_BACKUP="$KEY.backup-$(date +%Y%m%d-%H%M%S)"
    cp "$KEY" "$KEY_BACKUP"
    echo "[INFO] Key: existing private key backed up: $KEY_BACKUP"
  fi
  echo "[INFO] Key: generating new private key."
  echo "[INFO] Key path: $KEY"
  openssl genrsa -out "$KEY" "$SERVER_KEY_BITS"
  chmod 600 "$KEY"
fi

echo "[INFO] Generating CSR..."
openssl req -new \
  -key "$KEY" \
  -out "$CSR" \
  -config "$CNF"

echo "[INFO] Signing certificate with Intermediate CA..."
openssl x509 -req \
  -in "$CSR" \
  -CA "$INT_CERT" \
  -CAkey "$INT_KEY" \
  -CAcreateserial \
  -out "$CERT" \
  -days "$DAYS" \
  -sha256 \
  -extfile "$CNF" \
  -extensions v3_req
chmod 644 "$CERT"

cat "$CERT" "$INT_CERT" > "$FULLCHAIN"
cat "$INT_CERT" "$ROOT_CERT" > "$CHAIN"
chmod 644 "$FULLCHAIN" "$CHAIN"

openssl x509 -in "$CERT" -noout -text > "$TEXT"
chmod 644 "$TEXT"

echo "[INFO] Verifying certificate chain..."
openssl verify \
  -CAfile "$ROOT_CERT" \
  -untrusted "$INT_CERT" \
  "$CERT"

echo ""
echo "[OK] Certificate generated for: $FQDN"
echo ""
echo "Files:"
echo "  Config:     $CNF"
echo "  Key:        $KEY"
echo "  Cert:       $CERT"
echo "  Fullchain:  $FULLCHAIN"
echo "  Chain:      $CHAIN"
echo "  Text dump:  $TEXT"
echo ""
echo "Usually install on server/device:"
echo "  Certificate/fullchain: $FULLCHAIN"
echo "  Private key:           $KEY"
echo ""
echo "Trust on clients only once:"
echo "  Root CA:               $ROOT_CERT"
