# Home KISS PKI - Root CA + Intermediate CA

This is a very small home PKI using plain OpenSSL and shell scripts.

Design:

```text
Root CA -> Intermediate CA -> server/device certificates
```

Daily workflow:

```bash
./cert_gen.sh nas
```

No OpenSSL CA database, no CRL, no OCSP, no intermediate complexity in your daily command.

## 1. Configure defaults

Edit:

```bash
vi pki.env
```

Important defaults:

```bash
DEFAULT_DOMAIN="acme.test"
DEFAULT_IP="192.168.1.0"
EDITOR_CMD="vi"
```

`192.168.1.0` is included because it was requested as the default. In normal home networks this is usually the network address, not a device address. For real devices, use the actual device IP, for example `192.168.1.10`.

## 2. Initialise the CA

```bash
./init_ca.sh
```

This creates:

```text
ca/root/certs/root-ca.cert.pem
ca/root/private/root-ca.key.pem
ca/intermediate/certs/intermediate-ca.cert.pem
ca/intermediate/private/intermediate-ca.key.pem
```

Trust this certificate on clients:

```text
ca/root/certs/root-ca.cert.pem
```

Keep this key private/offline if possible:

```text
ca/root/private/root-ca.key.pem
```

Daily certificate signing uses the intermediate key:

```text
ca/intermediate/private/intermediate-ca.key.pem
```

## 3. Generate a device/server certificate

Interactive, opens config in `vi` before signing:

```bash
./cert_gen.sh nas
```

With a specific IP:

```bash
./cert_gen.sh nas --ip 192.168.1.10
```

Short form:

```bash
./cert_gen.sh nas 192.168.1.10
```

Non-interactive renewal/overwrite of certificate output files:

```bash
./cert_gen.sh nas --ip 192.168.1.10 --force
```

Important: `--force` now reuses an existing OpenSSL config and private key if they are already present. This is deliberate and is the safest default for renewals.

To deliberately rebuild the config from the template, add `--regen-config`:

```bash
./cert_gen.sh nas --ip 192.168.1.10 --force --regen-config
```

To deliberately create a new private key, add `--regen-key`:

```bash
./cert_gen.sh nas --ip 192.168.1.10 --force --regen-key
```

To rebuild both config and key:

```bash
./cert_gen.sh nas --ip 192.168.1.10 --force --regen-config --regen-key
```

Extra DNS names:

```bash
./cert_gen.sh nas --ip 192.168.1.10 --dns nas-01.acme.test --dns files.acme.test
```

Override domain if needed:

```bash
./cert_gen.sh router --domain lab.acme.test --ip 192.168.1.1
```

## 4. Output folder

Example:

```text
issued/nas.acme.test/
├── nas.acme.test.openssl.cnf
├── nas.acme.test.key.pem
├── nas.acme.test.csr.pem
├── nas.acme.test.cert.pem
├── nas.acme.test.fullchain.pem
├── nas.acme.test.chain.pem
└── nas.acme.test.cert.txt
```

Usually install these on the server/device:

```text
nas.acme.test.fullchain.pem
nas.acme.test.key.pem
```

Usually trust this only once on clients:

```text
ca/root/certs/root-ca.cert.pem
```

## 5. Renew or replace an existing server certificate

To replace an expired server/device certificate, generate a new certificate with the same hostname and SANs, then copy the new certificate and key to the device or service.

Because the Root CA and Intermediate CA stay the same, clients do not need to trust anything new.

Example: renew `nas.acme.test` with IP `192.168.1.10`:

```bash
./cert_gen.sh nas --ip 192.168.1.10 --force
```

For renewals, the script now reuses these files if they already exist:

```text
issued/nas.acme.test/nas.acme.test.openssl.cnf
issued/nas.acme.test/nas.acme.test.key.pem
```

It regenerates/overwrites these output files:

```text
issued/nas.acme.test/nas.acme.test.csr.pem
issued/nas.acme.test/nas.acme.test.cert.pem
issued/nas.acme.test/nas.acme.test.fullchain.pem
issued/nas.acme.test/nas.acme.test.chain.pem
issued/nas.acme.test/nas.acme.test.cert.txt
```

The important files are usually:

```text
nas.acme.test.key.pem        # private key
nas.acme.test.fullchain.pem  # server cert + intermediate CA
```

Some devices want the files separately:

```text
nas.acme.test.cert.pem       # server cert only
intermediate-ca.cert.pem    # intermediate CA
nas.acme.test.key.pem        # private key
```

Safer renewal workflow with backup:

```bash
cp -a issued/nas.acme.test "issued/nas.acme.test.backup-$(date +%Y%m%d)"
./cert_gen.sh nas --ip 192.168.1.10 --force
```

If you pass a new `--ip` or `--dns` value but an existing config file is present, the existing config wins. This is useful for exact renewals. The script logs this clearly, for example:

```text
[INFO] Config: reusing existing OpenSSL config.
[INFO] Config: --force preserves the existing config for safe renewals.
[INFO] Key: reusing existing private key.
[INFO] Key: --force preserves the existing key for safe renewals.
```

To apply new SANs from command-line arguments, either edit the config when it opens, or rebuild it from the template:

```bash
./cert_gen.sh nas --ip 192.168.1.20 --force --regen-config
```

If you really want a new key as well:

```bash
./cert_gen.sh nas --ip 192.168.1.20 --force --regen-config --regen-key
```

Check the new expiry date:

```bash
openssl x509 -in issued/nas.acme.test/nas.acme.test.cert.pem -noout -subject -issuer -dates
```

Check the SANs:

```bash
openssl x509 -in issued/nas.acme.test/nas.acme.test.cert.pem -noout -text | grep -A2 "Subject Alternative Name"
```

For normal server certificate renewal, do not replace the Root CA or Intermediate CA. Only the files under `issued/nas.acme.test/` change.

## 6. Trust the Root CA on clients

Only trust the Root CA certificate on clients:

```text
ca/root/certs/root-ca.cert.pem
```

Do not trust the intermediate separately unless a specific application or appliance requires it. Servers/devices should normally present their own server certificate plus the intermediate as `fullchain.pem`.

### macOS

System-wide trust:

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ./ca/root/certs/root-ca.cert.pem
```

### Windows

Run PowerShell or Command Prompt as Administrator for machine-wide trust:

```powershell
certutil -addstore -f Root .\ca\root\certs\root-ca.cert.pem
```

Current user only, without Administrator rights:

```powershell
certutil -user -addstore -f Root .\ca\root\certs\root-ca.cert.pem
```

PowerShell alternative, Administrator required for `LocalMachine`:

```powershell
Import-Certificate `
  -FilePath .\ca\root\certs\root-ca.cert.pem `
  -CertStoreLocation Cert:\LocalMachine\Root
```

Check that it was imported:

```powershell
certutil -store Root "ACME Root CA"
```

### Debian / Ubuntu

Install/update the CA certificates package if needed:

```bash
sudo apt update
sudo apt install -y ca-certificates
```

Copy the Root CA into the local trust anchor directory. Use a `.crt` extension:

```bash
sudo cp ./ca/root/certs/root-ca.cert.pem \
  /usr/local/share/ca-certificates/acme-root-ca.crt
sudo update-ca-certificates
```

Check that it was added:

```bash
ls -l /etc/ssl/certs | grep -i acme
```

### AlmaLinux / RHEL / Rocky Linux

Install/update the CA certificates package if needed:

```bash
sudo dnf install -y ca-certificates
```

Enable the dynamic CA trust store and add the Root CA:

```bash
sudo update-ca-trust enable
sudo cp ./ca/root/certs/root-ca.cert.pem \
  /etc/pki/ca-trust/source/anchors/acme-root-ca.pem
sudo update-ca-trust extract
```

Check that it was added:

```bash
trust list | grep -i "ACME Root CA" -A2
```

### FreeBSD

Copy the Root CA into the local certificate directory:

```sh
sudo cp ./ca/root/certs/root-ca.cert.pem \
  /usr/local/share/certs/acme-root-ca.crt
```

Rebuild the certificate hash links:

```sh
sudo certctl rehash
```

If `certctl` is not available on your FreeBSD version, use:

```sh
sudo c_rehash /usr/local/share/certs
```

Check that the certificate is visible:

```sh
ls -l /etc/ssl/certs | grep -i acme
```

### Important application notes

Some applications use their own trust stores and may not automatically use the operating system trust store. Common examples are Firefox/NSS profiles, Java keystores, some appliances, containers, and some bundled runtimes.

For those cases, import this same Root CA certificate into that application-specific trust store:

```text
ca/root/certs/root-ca.cert.pem
```

## 7. Verify manually

```bash
openssl verify \
  -CAfile ./ca/root/certs/root-ca.cert.pem \
  -untrusted ./ca/intermediate/certs/intermediate-ca.cert.pem \
  ./issued/nas.acme.test/nas.acme.test.cert.pem
```

## 8. Inspect SANs

```bash
openssl x509 -in ./issued/nas.acme.test/nas.acme.test.cert.pem -noout -text | grep -A2 "Subject Alternative Name"
```
