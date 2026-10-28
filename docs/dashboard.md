# TLS-aware Live Certificate Dashboard

This version adds a dedicated TLS endpoint:

```text
/__tls.json
```

The page behaviour is now:

- `http://...`  
  Header-only mode. Certificate and TLS panels are hidden. `/__certinfo.json` and `/__tls.json` are skipped.

- `https://...`  
  Full mode. The page shows:
  - certificate details from `/__certinfo.json`
  - TLS/session details from `/__tls.json`
  - request/response headers from `/__headers.json`
  - grouped raw diagnostics in a dedicated **RAW Data Diagnostics** panel

## Start HTTP only

```bash
mkdir -p www
cp server_certificate_dashboard_tls_aware.html www/index.html

python3 cert_dashboard_server_tls_aware.py \
  --directory ./www \
  --http-port 8080 \
  --https-port 0
```

Open:

```text
http://localhost:8080/
```

## Start HTTP + HTTPS

```bash
mkdir -p www
cp server_certificate_dashboard_tls_aware.html www/index.html

python3 cert_dashboard_server_tls_aware.py \
  --directory ./www \
  --http-port 8080 \
  --https-port 8443 \
  --cert ./certs/esxi-1.acme.test.cert.pem \
  --key  ./certs/esxi-1.acme.test.key.pem
```

Open:

```text
http://localhost:8080/      # header-only
https://localhost:8443/     # certificate + TLS + headers
```

## Test endpoints

```bash
curl http://localhost:8080/__headers.json
curl http://localhost:8080/__tls.json
curl -k https://localhost:8443/__certinfo.json
curl -k https://localhost:8443/__tls.json
curl -k https://localhost:8443/__headers.json
```

## What `/__tls.json` can show

For HTTPS requests, it reports:

- TLS enabled yes/no
- negotiated TLS protocol, for example TLSv1.3
- negotiated cipher
- cipher protocol and secret bits
- ALPN/NPN where available
- compression status
- local and remote socket addresses
- client certificate presence for mTLS
- Python SSL/OpenSSL runtime version
- configured cert/key path presence
- configured minimum TLS version
- shared cipher snapshot when exposed by Python/OpenSSL
- channel binding length and SHA-256 hash when available

## Important limitation

The Python standard library cannot expose every detail of the browser TLS handshake.
For a full external TLS audit, use tools such as:

```bash
openssl s_client -connect localhost:8443 -servername localhost
nmap --script ssl-enum-ciphers -p 8443 localhost
testssl.sh https://localhost:8443
```


## RAW Data Diagnostics panel

The following debug-heavy sections are now grouped together in one dedicated panel:

- PEM Certificate
- Raw Certificate JSON / Parser Diagnostics
- Raw TLS JSON

This keeps the main dashboard clean while still keeping all raw troubleshooting data available.


## Final polish update

- The live status notice now sits compactly inside the hero area as an overlay.
- The notice no longer adds height to the hero section.
- Crypto values now use the same monospace styling as the technical Identity fields.
- Common Name under Identity now also uses monospace styling.


## Mono font size tweak

- `.mono` font size changed from `13px` to `12px`.


## Final tidy update

- All three RAW Data Diagnostics disclosure labels now read `Show / hide`.
- `Raw TLS JSON` renamed to `TLS JSON returned by the server`.
- `Raw Certificate JSON / Parser Diagnostics` renamed to `Certificate JSON returned by the server`.
- Footer endpoint references are now clickable links:
  - `/__certinfo.json`
  - `/__tls.json`
  - `/__headers.json`


## Uploaded Certificate / Key Inspector

This version adds a dashboard upload panel and a new endpoint:

```text
/__upload_inspect.json
```

The upload inspector lets you choose a certificate file, certificate chain, DER certificate, and/or a private key file. It displays certificate summaries, chain entries, key details, and whether the uploaded certificate and private key match. The running web server certificate is not replaced. Files are parsed for the current request only and are not kept.

Example:

```bash
curl -k https://localhost:8443/__upload_inspect.json \
  -F "certificate=@./certs/esxi-1.acme.test.cert.pem" \
  -F "privateKey=@./certs/esxi-1.acme.test.key.pem"
```

With encrypted key:

```bash
curl -k https://localhost:8443/__upload_inspect.json \
  -F "certificate=@./certs/esxi-1.acme.test.cert.pem" \
  -F "privateKey=@./certs/esxi-1.acme.test.key.pem" \
  -F "passphrase=your-passphrase"
```


## Upload inspector fix

This version fixes upload parsing and encrypted key detection. It uses Python's standard library MIME parser, accepts PEM/chain/DER certs more reliably, trims harmless BOM/CRLF, detects encrypted PKCS#8 private keys more accurately, and returns a clear passphrase hint instead of a long OpenSSL provider dump.
