# KISS PKI in Docker

A small PKI (Root CA → Intermediate CA → server certificates) packaged as a container, together with a Python dashboard that serves the root CA for download, shows certificate/TLS details, and (optionally) lets you browse, download and issue certificates from the browser.

## Documentation

| Document | What it covers |
|---|---|
| [PKI documentation](docs/pki.md) | The PKI itself: `pki.env`, `init_ca.sh`, `cert_gen.sh` options, renewals, trusting the root CA on macOS / Windows / Linux / FreeBSD, manual verification |
| [Dashboard documentation](docs/dashboard.md) | The dashboard page and its endpoints (`/__certinfo.json`, `/__tls.json`, `/__headers.json`, `/__upload_inspect.json`), the upload inspector, HTTP vs. HTTPS behaviour |

This file covers only what is specific to the container. The dashboard README describes the standalone script, so ignore its start commands (`python3 ... --cert ...`); the container starts it for you.

## Contents

```text
.
├── Dockerfile
├── docker-compose.yml
├── docker-entrypoint.sh     # serve / idle / init / cert / shell / help
├── cert_dashboard.py        # dashboard web server
├── index.html               # dashboard page
├── build_docs.py            # renders the Markdown docs to HTML at image build time
├── init_ca.sh               # create Root + Intermediate CA
├── cert_gen.sh              # issue server certificates
├── pki.env                  # defaults (domain, validity, ...)
├── templates/               # OpenSSL config templates
├── docs/                    # READMEs linked above
└── data/                    # created on first start, bind-mounted
    ├── ca/                  # root + intermediate keys and certificates
    └── issued/              # one folder per issued certificate
```

The scripts and templates are baked into the image. `ca/` and `issued/` are never part of the image; they live in `./data` on the host, so the CA survives rebuilds.

## Quick start

```bash
# 1. Files in ./data should belong to you, not root
export PKI_UID=$(id -u) PKI_GID=$(id -g)

# 2. Settings go in .env (chmod 600), see "Configuration"
cat > .env <<'EOF'
PKI_UID=1000
PKI_GID=1000
PKI_WEB_IP=192.168.1.50
PKI_BROWSE_PASSWORD=choose-a-long-passphrase
EOF
chmod 600 .env

# 3. Build and start
docker compose up -d --build
docker compose logs -f pki
```

On first start the container:

1. creates the Root and Intermediate CA if `data/ca` is empty,
2. issues a certificate for the dashboard itself (`pki.<DEFAULT_DOMAIN>`), and renews it when fewer than 30 days remain,
3. publishes the **public** root CA certificate for download,
4. starts the dashboard on HTTP (8080) and HTTPS (8443).

Open `http://<docker-host>:8080/` to download the root CA, or `https://<docker-host>:8443/` for the full dashboard. Browsers will warn about the HTTPS certificate until the root CA is trusted on that client; download it from the HTTP page first.

## Configuration

Set these in `.env` next to `docker-compose.yml`. Compose reads `.env` automatically.

| Variable | Default | Purpose |
|---|---|---|
| `PKI_UID`, `PKI_GID` | `1000` | Container user; owner of files in `./data` |
| `PKI_WEB_HOST` | `pki` | Dashboard certificate host name (becomes `pki.<domain>`) |
| `PKI_WEB_IP` | empty | IP address in the dashboard certificate. Set this to the Docker host's LAN IP |
| `PKI_WEB_DNS` | empty | Extra DNS names, comma separated |
| `PKI_BROWSE_USER` | `admin` | User name for the issued-certificate browser |
| `PKI_BROWSE_PASSWORD` | empty | Enables the issued-certificate browser. At least 12 characters |
| `PKI_WEB_ISSUE` | `false` | `true` lets the dashboard issue certificates (see the warning below) |
| `PKI_HTTP_HOST_PORT` | `8080` | Host port for HTTP |
| `PKI_HTTPS_HOST_PORT` | `8443` | Host port for HTTPS |

PKI defaults such as `DEFAULT_DOMAIN` and certificate validity are in `pki.env`, bind-mounted read-only, so editing it needs only a restart.

Gotchas:

- A `$` in a `.env` value is interpolated by Compose. Write `$$` for a literal dollar sign.
- `docker compose restart` does not re-read `.env`; use `docker compose up -d`.
- Code changes (`cert_dashboard.py`, `index.html`, scripts) need `docker compose up -d --build`.

## Dashboard features

| Feature | Available on | Notes |
|---|---|---|
| Root CA download (`.pem`, `.crt`, SHA-256 fingerprint) | HTTP and HTTPS | Public certificate only, never a key. This is the one to install on clients |
| Intermediate CA and CA bundle (`ca-chain.pem` = intermediate + root) | HTTP and HTTPS | Public only; for applications that ask for the intermediate or a bundle |
| Certificate, TLS, headers and diagnostics panels | HTTPS | Hidden on plain HTTP |
| Upload inspector | HTTP and HTTPS | Parses uploaded certificate/key for that request only |
| Issued certificates: browse and download certificates, keys, zip per host | HTTPS only | Needs `PKI_BROWSE_PASSWORD` |
| Issue or renew a certificate | HTTPS only | Needs `PKI_BROWSE_PASSWORD` and `PKI_WEB_ISSUE=true` |

### Issued-certificate browser

Downloads include private keys, so access is protected:

- HTTPS only (plain HTTP gets 403) with HTTP Basic authentication.
- 10 failed logins from one address within 5 minutes lock that address out (429).
- Strict file name checks; symlinks and path traversal are rejected.
- Every download is written to the container log.

Treat the dashboard as a LAN-only service. Do not publish port 8443 to the internet.

### Issuing certificates from the web

When `PKI_WEB_ISSUE=true`, the HTTPS page shows an **Issue or renew a certificate** form (hostname, IP addresses, extra DNS names, domain override, validity days, force / regen-config / regen-key). It runs `cert_gen.sh` non-interactively and shows its output.

> **Warning:** this gives the web process, and anyone holding the browse password, the ability to sign certificates with the intermediate CA key. Leave it off unless you want that, and use a long, unique password.

It is protected by the same HTTPS and password checks, rejects cross-origin and non-JSON requests, validates every input, passes arguments without a shell, and runs one generation at a time.

## Command line

```bash
# Issue a certificate (same arguments as cert_gen.sh)
docker compose exec pki pki cert nas --ip 192.168.1.10
docker compose exec pki pki cert nas --ip 192.168.1.10 --dns files.acme.test
docker compose exec pki pki cert nas --ip 192.168.1.10 --force      # renew

# Interactive config edit (opens vi before signing); needs a terminal
docker compose exec -it pki pki cert nas --ip 192.168.1.10

# Other commands
docker compose exec pki pki shell
docker compose run --rm pki init       # create the CA only
docker compose run --rm pki help
```

The service is called `pki` (the container is typically `<folder>-pki-1`). Use the service name with `docker compose exec`.

Results appear under `data/issued/<fqdn>/`. Usually you install `<fqdn>.fullchain.pem` and `<fqdn>.key.pem` on the device. See [docs/pki.md](docs/pki.md) for renewal rules (`--force`, `--regen-config`, `--regen-key`).

### Keeping the container running without the dashboard

Change `command: ["serve"]` to `command: ["idle"]` in `docker-compose.yml` to keep a resident container for `exec` work only.

## Backup

Everything that matters is in `./data`:

```bash
tar czf pki-backup-$(date +%Y%m%d).tar.gz data/
```

`data/ca` holds the root and intermediate **private keys**. Store backups encrypted and offline, and keep the root key off the running host if you can.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Build fails with `401 Unauthorized` from Docker Hub | Run `docker logout`, check `~/.docker/config.json`, proxy or mirror settings |
| "The issued-certificate browser is disabled" | `PKI_BROWSE_PASSWORD` is empty or shorter than 12 characters. Check with `docker compose exec pki sh -c 'echo ${#PKI_BROWSE_PASSWORD}'`, then `docker compose up -d` |
| Password length is shorter than expected | A `$` was interpolated; escape it as `$$` |
| No "Issue" form on the page | `PKI_WEB_ISSUE` is not `true`, or the browser is disabled; check `docker compose logs pki \| grep -i generation` |
| `service "pki-1" is not running` | Use the service name: `docker compose exec pki ...` |
| Permission errors on `./data` | Set `PKI_UID` / `PKI_GID` to your user and fix ownership of `./data` |
| Browser warns about the HTTPS certificate | Trust the root CA on that client (see [docs/pki.md](docs/pki.md), section 6) |
| Dashboard certificate lacks the host's IP | Set `PKI_WEB_IP`; delete `data/issued/pki.<domain>` and restart to re-issue |
| Health check | `curl http://<host>:8080/__health.json` |
