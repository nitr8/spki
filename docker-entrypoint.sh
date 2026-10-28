#!/usr/bin/env bash
set -euo pipefail
cd /app

usage() {
  cat <<'USAGE'
Home KISS PKI (container)

Commands:
  serve                 Run the certificate dashboard (HTTP + HTTPS) in the foreground.
                        Auto-initialises the CA and issues/renews the dashboard's own
                        certificate if needed.
  idle                  Keep the container running without the web server
                        (for `docker compose exec` work only).
  init                  Create Root + Intermediate CA (idempotent)
  cert HOST [args...]   Issue a certificate (same args as cert_gen.sh)
  shell                 Open a bash shell in the container
  help                  Show this help

Environment (used by `serve`):
  PKI_WEB_HOST    Hostname of the dashboard cert (default: pki -> pki.<DEFAULT_DOMAIN>)
  PKI_WEB_IP      IP address SAN for the dashboard cert (recommended: the Docker host's LAN IP)
  PKI_WEB_DNS     Extra DNS SANs, comma separated
  PKI_BROWSE_USER      User for the issued-certificate browser (default: admin)
  PKI_BROWSE_PASSWORD  Enables the issued-certificate browser (cert/key downloads).
                       Min. 12 characters; served over HTTPS only.
  PKI_WEB_ISSUE        true = allow issuing certificates from the dashboard (runs cert_gen.sh
                       with the intermediate CA). Requires PKI_BROWSE_PASSWORD. Default: off.
  PKI_HTTP_PORT   HTTP port inside the container (default 8080, 0 = disable)
  PKI_HTTPS_PORT  HTTPS port inside the container (default 8443, 0 = disable)

Examples:
  docker compose up -d
  docker compose exec pki pki cert nas --ip 192.168.1.10
  docker compose exec pki pki cert nas --ip 192.168.1.10 --force
  docker compose run --rm pki init
USAGE
}

serve() {
  # shellcheck source=/dev/null
  source ./pki.env

  if [[ ! -f ca/root/certs/root-ca.cert.pem || ! -f ca/intermediate/certs/intermediate-ca.cert.pem ]]; then
    echo "[INFO] CA not initialised yet - running init_ca.sh"
    ./init_ca.sh
  fi

  # Publish the PUBLIC root CA certificate for client download (never any key).
  # Two names: .pem for Linux/macOS, .crt so Windows opens it natively.
  cp -f ca/root/certs/root-ca.cert.pem www/root-ca.cert.pem
  cp -f ca/root/certs/root-ca.cert.pem www/root-ca.crt
  openssl x509 -in ca/root/certs/root-ca.cert.pem -noout -fingerprint -sha256 \
    | cut -d= -f2 > www/root-ca.sha256.txt
  # Intermediate CA and a chain bundle (intermediate + root), also public. Most clients only need
  # the root; these are for applications that ask for the intermediate or for a CA bundle.
  cp -f ca/intermediate/certs/intermediate-ca.cert.pem www/intermediate-ca.cert.pem
  cp -f ca/intermediate/certs/intermediate-ca.cert.pem www/intermediate-ca.crt
  cat ca/intermediate/certs/intermediate-ca.cert.pem ca/root/certs/root-ca.cert.pem > www/ca-chain.pem
  openssl x509 -in ca/intermediate/certs/intermediate-ca.cert.pem -noout -fingerprint -sha256 \
    | cut -d= -f2 > www/intermediate-ca.sha256.txt
  chmod 644 www/root-ca.cert.pem www/root-ca.crt www/root-ca.sha256.txt \
    www/intermediate-ca.cert.pem www/intermediate-ca.crt www/ca-chain.pem www/intermediate-ca.sha256.txt

  local host domain fqdn dir cert key
  host="$(echo "${PKI_WEB_HOST:-pki}" | tr '[:upper:]' '[:lower:]')"
  domain="$(echo "$DEFAULT_DOMAIN" | tr '[:upper:]' '[:lower:]')"
  if [[ "$host" == *.* ]]; then fqdn="$host"; else fqdn="$host.$domain"; fi

  dir="issued/$fqdn"
  cert="$dir/$fqdn.fullchain.pem"
  key="$dir/$fqdn.key.pem"

  local -a args=("$host" --no-edit)
  if [[ -n "${PKI_WEB_IP:-}" ]]; then
    args+=(--ip "$PKI_WEB_IP")
  fi
  if [[ -n "${PKI_WEB_DNS:-}" ]]; then
    local -a extra
    IFS=',' read -ra extra <<< "$PKI_WEB_DNS"
    local d
    for d in "${extra[@]}"; do
      if [[ -n "$d" ]]; then args+=(--dns "$d"); fi
    done
  fi

  if [[ ! -f "$dir/$fqdn.cert.pem" || ! -f "$key" ]]; then
    echo "[INFO] Dashboard certificate for $fqdn not found - issuing"
    ./cert_gen.sh "${args[@]}"
  elif ! openssl x509 -in "$dir/$fqdn.cert.pem" -noout -checkend $((30 * 86400)) >/dev/null; then
    echo "[INFO] Dashboard certificate for $fqdn expires within 30 days - renewing (same key and config)"
    ./cert_gen.sh "${args[@]}" --force
  else
    echo "[INFO] Dashboard certificate for $fqdn is valid"
  fi

  exec python3 cert_dashboard.py \
    --directory ./www \
    --http-port "${PKI_HTTP_PORT:-8080}" \
    --https-port "${PKI_HTTPS_PORT:-8443}" \
    --cert "$cert" \
    --key "$key" \
    --issued-dir ./issued \
    --browse-user "${PKI_BROWSE_USER:-admin}" \
    --pki-dir .
}

cmd="${1:-help}"
shift || true

case "$cmd" in
  serve)          serve ;;
  idle)           echo "[INFO] Idling. Use: docker compose exec pki pki cert HOST ..."; exec tail -f /dev/null ;;
  init)           exec ./init_ca.sh "$@" ;;
  cert)           exec ./cert_gen.sh "$@" ;;
  shell|bash|sh)  exec bash "$@" ;;
  help|-h|--help) usage ;;
  *)              exec "$cmd" "$@" ;;   # allow arbitrary commands, e.g. openssl ...
esac
