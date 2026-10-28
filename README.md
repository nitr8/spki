# KISS PKI

A small, self-hosted PKI for home labs and offline networks: **Root CA → Intermediate CA → server certificates**, using plain OpenSSL and shell scripts, packaged as a container with a Python dashboard.

[![Docker Hub](https://img.shields.io/docker/v/YOUR_USER/kiss-pki?label=Docker%20Hub&sort=semver)](https://hub.docker.com/r/YOUR_USER/kiss-pki)
[![Build](https://github.com/YOUR_USER/kiss-pki/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/YOUR_USER/kiss-pki/actions/workflows/docker-publish.yml)

```bash
docker compose exec pki pki cert nas --ip 192.168.1.10
```

That's the daily workflow. No CA database, no CRL, no OCSP.

## Why

Running your own CA for a NAS, hypervisor, router or internal web service usually means either self-signed certificates and browser warnings everywhere, or a heavyweight CA product. KISS PKI sits in between: trust one root certificate once on each client, then issue properly chained certificates with a single command.

## Features

- Two-tier CA (Root + Intermediate), created automatically on first start
- Server certificates with IP and DNS SANs
- Safe renewals: existing key and config are reused unless you ask for new ones
- Dashboard over HTTP and HTTPS
  - Root CA, intermediate and CA bundle download with SHA-256 fingerprint
  - Certificate, TLS session and header panels
  - Upload inspector for certificates, chains and keys
- Optional password-protected browser for issued certificates
- Optional certificate issuing from the web (off by default)
- CA data stays on the host and survives rebuilds

## Quick start

```bash
git clone https://github.com/YOUR_USER/kiss-pki.git
cd kiss-pki

cat > .env <<'EOF'
PKI_UID=1000
PKI_GID=1000
PKI_WEB_IP=192.168.1.50
PKI_BROWSE_PASSWORD=choose-a-long-passphrase
EOF
chmod 600 .env

docker compose up -d --build
```

Then:

1. Open `http://<docker-host>:8080/` and download the root CA.
2. Trust it on your clients (see [PKI documentation, section 6](docs/pki.md#6-trust-the-root-ca-on-clients)).
3. Open `https://<docker-host>:8443/` for the full dashboard.
4. Issue certificates:
   ```bash
   docker compose exec pki pki cert nas --ip 192.168.1.10
   ```
   Output is in `data/issued/nas.acme.test/`. Install `*.fullchain.pem` and `*.key.pem` on the device.

Prefer the prebuilt image? Use [`YOUR_USER/kiss-pki`](https://hub.docker.com/r/YOUR_USER/kiss-pki) from Docker Hub.

## Documentation

| Document | What it covers |
|---|---|
| [Container](docs/container.md) | Docker setup, `.env` options, commands, backup, troubleshooting |
| [PKI](docs/pki.md) | `pki.env`, `init_ca.sh`, `cert_gen.sh` options, renewals, trusting the root CA on macOS / Windows / Linux / FreeBSD |
| [Dashboard](docs/dashboard.md) | Dashboard endpoints, upload inspector, HTTP vs. HTTPS behaviour |

The scripts also work without Docker. See the PKI documentation.

## Repository layout

```text
.
├── Dockerfile
├── docker-compose.yml
├── docker-entrypoint.sh
├── cert_dashboard.py        # dashboard web server
├── index.html               # dashboard page
├── init_ca.sh               # create Root + Intermediate CA
├── cert_gen.sh              # issue server certificates
├── pki.env                  # defaults (domain, validity, key sizes)
├── templates/               # OpenSSL config templates
└── docs/
```

`data/` is created on first start and is excluded from Git. **Never commit it**: it contains your CA private keys.

## Security

- Intended for trusted LANs. Do not expose the dashboard to the internet.
- Back up `data/` encrypted and offline. Keep the root key off the running host if you can.
- Web issuing (`PKI_WEB_ISSUE=true`) lets anyone with the browse password sign certificates. Leave it off unless you need it.

Found a security problem? Please open a private security advisory rather than a public issue.

## License

[MIT](LICENSE)
