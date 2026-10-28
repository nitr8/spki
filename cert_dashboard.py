#!/usr/bin/env python3
"""
cert_dashboard_server_fixed.py

Static file server with optional HTTPS and robust JSON endpoints:

  /__certinfo.json  - certificate details parsed from --cert
  /__headers.json   - request headers echoed back as JSON
  /__health.json    - quick status / configuration check
  /__issued.json    - list of issued certificates (password + HTTPS only)
  /__issue.json     - POST: generate a certificate with cert_gen.sh (opt-in, password + HTTPS only)
  /__issued/<host>/<file> and /__issued/<host>.zip - downloads (password + HTTPS only)

This fixed version intentionally avoids fragile Python certificate internals.
It parses the first certificate in a PEM file or chain using `openssl x509`.

Examples:

  mkdir -p www
  cp server_certificate_dashboard_live_fixed.html www/index.html

  python3 cert_dashboard_server_fixed.py \
    --directory ./www \
    --http-port 8080 \
    --https-port 8443 \
    --cert ./certs/esxi-1.acme.test.cert.pem \
    --key  ./certs/esxi-1.acme.test.key.pem

Test:

  curl -k https://localhost:8443/__health.json
  curl -k https://localhost:8443/__certinfo.json
  curl -k https://localhost:8443/__headers.json
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import http.server
import io
import ipaddress
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
from functools import partial
from pathlib import Path
from typing import Any


CERT_PATH: Path | None = None
KEY_PATH: Path | None = None
STARTED_AT = dt.datetime.now(dt.timezone.utc)
TLS_MIN_VERSION_NAME = "TLSv1.2"
SNI_CALLBACK_USED = False


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def log(level: str, message: str) -> None:
    print(f"[{level}] {message}", file=sys.stderr)


def json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    return str(value)


def pem_first_certificate(pem_text: str) -> str:
    match = re.search(
        r"-----BEGIN CERTIFICATE-----\s*.*?\s*-----END CERTIFICATE-----",
        pem_text,
        flags=re.DOTALL,
    )
    if not match:
        raise ValueError("No PEM certificate block found. Expected -----BEGIN CERTIFICATE-----")
    return match.group(0) + "\n"


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


def run_openssl_x509(first_cert_pem: str, *args: str) -> str:
    if not openssl_available():
        raise RuntimeError("openssl command not found in PATH")

    cmd = ["openssl", "x509", "-noout", *args]
    proc = subprocess.run(
        cmd,
        input=first_cert_pem,
        text=True,
        capture_output=True,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            "openssl x509 failed: "
            + (proc.stderr.strip() or proc.stdout.strip() or f"return code {proc.returncode}")
        )

    return proc.stdout


def run_openssl_x509_der(first_cert_pem: str) -> bytes:
    if not openssl_available():
        raise RuntimeError("openssl command not found in PATH")

    cmd = ["openssl", "x509", "-outform", "DER"]
    proc = subprocess.run(
        cmd,
        input=first_cert_pem,
        text=True,
        capture_output=True,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            "openssl x509 DER export failed: "
            + (proc.stderr.strip() or proc.stdout.strip() or f"return code {proc.returncode}")
        )

    return proc.stdout.encode("latin1")


def run_openssl_x509_der_bytes(first_cert_pem: str) -> bytes:
    if not openssl_available():
        raise RuntimeError("openssl command not found in PATH")

    cmd = ["openssl", "x509", "-outform", "DER"]
    proc = subprocess.run(
        cmd,
        input=first_cert_pem.encode("utf-8"),
        capture_output=True,
    )

    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace")
        stdout = proc.stdout.decode("utf-8", errors="replace")
        raise RuntimeError(
            "openssl x509 DER export failed: "
            + (stderr.strip() or stdout.strip() or f"return code {proc.returncode}")
        )

    return proc.stdout


def colon_hex(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw)


def serial_with_colons(value: str) -> str:
    raw = value.strip()
    if raw.startswith("serial="):
        raw = raw.split("=", 1)[1]
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw)
    if not cleaned:
        return raw
    if len(cleaned) % 2:
        cleaned = "0" + cleaned
    return ":".join(cleaned[i:i + 2].upper() for i in range(0, len(cleaned), 2))


def split_dn(value: str) -> str:
    # Openssl can output either:
    # subject=CN = host, O = Org
    # or subject=/CN=host/O=Org
    value = value.strip()
    value = re.sub(r"^(subject|issuer)\s*=\s*", "", value)
    if value.startswith("/"):
        parts = [p for p in value.split("/") if p]
        return ", ".join(parts)
    value = re.sub(r"\s+=\s+", "=", value)
    return value


def cn_from_subject(subject: str) -> str:
    match = re.search(r"(?:^|,\s*)CN=([^,]+)", subject)
    if match:
        return match.group(1).strip()
    match = re.search(r"(?:^|/)CN=([^/]+)", subject)
    if match:
        return match.group(1).strip()
    return ""


def parse_openssl_date(value: str) -> str | None:
    # Example:
    # notBefore=May 28 19:40:00 2026 GMT
    # notAfter=May 28 19:40:00 2027 GMT
    raw = value.strip()
    if "=" in raw:
        raw = raw.split("=", 1)[1].strip()

    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            parsed = dt.datetime.strptime(raw, fmt)
            return parsed.replace(tzinfo=dt.timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            pass

    return raw or None


def first_line(output: str) -> str:
    for line in output.splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def extension_value_lines(text: str, extension_name: str) -> list[str]:
    lines = text.splitlines()
    out: list[str] = []

    for idx, line in enumerate(lines):
        if extension_name in line:
            for value_line in lines[idx + 1:]:
                stripped = value_line.strip()
                if not stripped:
                    break
                if stripped.startswith("X509v3 ") or stripped.startswith("Signature Algorithm:"):
                    break
                if stripped.startswith("TLS Feature:"):
                    break
                if stripped.lower() == "critical":
                    continue
                out.append(stripped)
            break

    return out


def extension_values_split(text: str, extension_name: str) -> list[str]:
    values: list[str] = []
    for line in extension_value_lines(text, extension_name):
        values.extend([v.strip() for v in line.split(",") if v.strip()])

    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def parse_sans(text: str) -> list[str]:
    raw_values = extension_values_split(text, "X509v3 Subject Alternative Name")
    result: list[str] = []

    for value in raw_values:
        clean = value.strip()
        clean = clean.replace("DNS:", "DNS:")
        clean = clean.replace("IP Address:", "IP:")
        result.append(clean)

    return result


def extract_public_key(text: str) -> str:
    alg = ""
    bits = ""

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Public Key Algorithm:"):
            alg = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Public-Key:"):
            bits = stripped.split(":", 1)[1].strip().strip("()")

    if alg and bits:
        return f"{alg} {bits}"
    return alg or bits or "unavailable"


def extract_signature_algorithm(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Signature Algorithm:"):
            return stripped.split(":", 1)[1].strip()
    return "unavailable"


def extract_version(text: str) -> str:
    match = re.search(r"^\s*Version:\s*(.+)$", text, flags=re.MULTILINE)
    return match.group(1).strip() if match else "X.509"


def certificate_json() -> dict[str, Any]:
    diagnostics: list[str] = []

    if CERT_PATH is None:
        return {
            "ok": False,
            "error": "No certificate path configured. Start with --cert /path/to/server.cert.pem",
            "generatedAt": now_iso(),
        }

    if not CERT_PATH.exists():
        return {
            "ok": False,
            "error": f"Certificate file not found: {CERT_PATH}",
            "generatedAt": now_iso(),
            "configuredCertPath": str(CERT_PATH),
        }

    try:
        pem_text = CERT_PATH.read_text(encoding="utf-8")
        first_cert = pem_first_certificate(pem_text)
        diagnostics.append("Loaded first PEM certificate block from configured cert file.")
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Unable to read PEM certificate: {exc}",
            "generatedAt": now_iso(),
            "configuredCertPath": str(CERT_PATH),
        }

    try:
        text = run_openssl_x509(first_cert, "-text")
        subject_raw = first_line(run_openssl_x509(first_cert, "-subject"))
        issuer_raw = first_line(run_openssl_x509(first_cert, "-issuer"))
        serial_raw = first_line(run_openssl_x509(first_cert, "-serial"))
        dates_raw = run_openssl_x509(first_cert, "-dates")
        sha256_raw = first_line(run_openssl_x509(first_cert, "-fingerprint", "-sha256"))
        sha1_raw = first_line(run_openssl_x509(first_cert, "-fingerprint", "-sha1"))
        der = run_openssl_x509_der_bytes(first_cert)
        diagnostics.append("Parsed certificate using openssl x509.")
    except Exception as exc:
        return {
            "ok": False,
            "error": f"OpenSSL parser failed: {exc}",
            "generatedAt": now_iso(),
            "configuredCertPath": str(CERT_PATH),
            "opensslFound": openssl_available(),
            "pemPreview": first_cert[:200],
        }

    dates: dict[str, str] = {}
    for line in dates_raw.splitlines():
        if line.startswith("notBefore="):
            dates["notBefore"] = parse_openssl_date(line) or line
        elif line.startswith("notAfter="):
            dates["notAfter"] = parse_openssl_date(line) or line

    subject = split_dn(subject_raw)
    issuer = split_dn(issuer_raw)
    common_name = cn_from_subject(subject)

    # Fingerprints from openssl output first, hashes as fallback.
    sha256 = sha256_raw.split("=", 1)[1].strip() if "=" in sha256_raw else colon_hex(hashlib.sha256(der).digest())
    sha1 = sha1_raw.split("=", 1)[1].strip() if "=" in sha1_raw else colon_hex(hashlib.sha1(der).digest())

    return {
        "ok": True,
        "pageTitle": common_name or CERT_PATH.stem,
        "subtitle": f"Live certificate information loaded from {CERT_PATH.name}",
        "commonName": common_name,
        "subject": subject,
        "issuer": issuer,
        "serialNumber": serial_with_colons(serial_raw),
        "version": extract_version(text),
        "publicKey": extract_public_key(text),
        "signatureAlgorithm": extract_signature_algorithm(text),
        "isCA": "CA:TRUE" in text,
        "notBefore": dates.get("notBefore"),
        "notAfter": dates.get("notAfter"),
        "subjectAlternativeNames": parse_sans(text),
        "keyUsage": extension_values_split(text, "X509v3 Key Usage"),
        "extendedKeyUsage": extension_values_split(text, "X509v3 Extended Key Usage"),
        "fingerprints": {
            "sha256": sha256,
            "sha1": sha1,
        },
        "pem": first_cert,
        "source": str(CERT_PATH),
        "configuredCertPath": str(CERT_PATH),
        "configuredKeyPath": str(KEY_PATH) if KEY_PATH else None,
        "opensslFound": openssl_available(),
        "generatedAt": now_iso(),
        "diagnostics": diagnostics,
    }


def cipher_tuple_to_dict(cipher: Any) -> dict[str, Any] | None:
    if not cipher:
        return None

    if isinstance(cipher, tuple):
        # Python returns: (cipher_name, protocol_version, secret_bits)
        return {
            "name": cipher[0] if len(cipher) > 0 else None,
            "protocol": cipher[1] if len(cipher) > 1 else None,
            "secretBits": cipher[2] if len(cipher) > 2 else None,
        }

    return {"value": str(cipher)}


def shared_ciphers_to_list(shared: Any) -> list[dict[str, Any]]:
    if not shared:
        return []

    result: list[dict[str, Any]] = []
    for item in shared:
        if isinstance(item, tuple):
            result.append({
                "name": item[0] if len(item) > 0 else None,
                "protocol": item[1] if len(item) > 1 else None,
                "bits": item[2] if len(item) > 2 else None,
            })
        else:
            result.append({"name": str(item), "protocol": None, "bits": None})
    return result


def safe_call(func: Any, default: Any = None) -> Any:
    try:
        return func()
    except Exception:
        return default


def cert_name_to_string(name_tuple: Any) -> str:
    if not name_tuple:
        return ""

    parts: list[str] = []
    for rdn in name_tuple:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def peer_cert_summary(sock: ssl.SSLSocket) -> dict[str, Any]:
    cert = safe_call(lambda: sock.getpeercert(), None)
    binary = safe_call(lambda: sock.getpeercert(binary_form=True), None)

    summary: dict[str, Any] = {
        "present": bool(cert or binary),
        "subject": None,
        "issuer": None,
        "serialNumber": None,
        "notBefore": None,
        "notAfter": None,
        "sha256": None,
    }

    if isinstance(cert, dict):
        summary.update({
            "subject": cert_name_to_string(cert.get("subject")),
            "issuer": cert_name_to_string(cert.get("issuer")),
            "serialNumber": cert.get("serialNumber"),
            "notBefore": cert.get("notBefore"),
            "notAfter": cert.get("notAfter"),
        })

    if binary:
        summary["sha256"] = colon_hex(hashlib.sha256(binary).digest())

    return summary




MAX_UPLOAD_BYTES = 12 * 1024 * 1024


def clean_upload_bytes(data: bytes) -> bytes:
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data.strip(b"\r\n")


def split_pem_certificates(data: bytes) -> list[bytes]:
    text = data.decode("utf-8", errors="ignore")
    matches = re.findall(
        r"-----BEGIN\s+CERTIFICATE-----.*?-----END\s+CERTIFICATE-----",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    return [(m.strip() + "\n").encode("utf-8") for m in matches]


def looks_like_der_certificate(data: bytes) -> bool:
    data = clean_upload_bytes(data)
    return len(data) > 4 and data[0] == 0x30 and data[1] in (0x80, 0x81, 0x82, 0x83)


def run_cmd(cmd: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(cmd, input=input_bytes, capture_output=True)


def concise_openssl_error(stderr: bytes, stdout: bytes = b"") -> str:
    text = (stderr or stdout).decode("utf-8", errors="replace").strip()
    if not text:
        return "OpenSSL command failed"
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    useful: list[str] = []
    for line in lines:
        lower = line.lower()
        if "bad decrypt" in lower:
            useful.append("Bad decrypt: wrong passphrase or unsupported encrypted key format.")
        elif "unable to get passphrase" in lower or "problems getting password" in lower:
            useful.append("Private key is encrypted and needs a passphrase.")
        elif "input structure: encryptedprivatekeyinfo" in lower:
            useful.append("Private key is encrypted PKCS#8 and needs a passphrase.")
        elif "no supported data to decode" in lower:
            useful.append("OpenSSL could not decode the uploaded key/certificate data.")
        elif "unsupported" in lower and ("decoder" in lower or "store" in lower):
            useful.append("OpenSSL decoder/provider could not read this input without the right passphrase/provider.")
        elif "unable to load" in lower or "could not" in lower:
            useful.append(line)
    if useful:
        seen=set(); out=[]
        for item in useful:
            if item not in seen:
                seen.add(item); out.append(item)
        return " ".join(out)
    return lines[-1][:800]


def openssl_x509_from_file(cert_path: Path, *args: str) -> str:
    if not openssl_available():
        raise RuntimeError("openssl command not found in PATH")
    proc = run_cmd(["openssl", "x509", "-in", str(cert_path), "-noout", *args])
    if proc.returncode != 0:
        raise RuntimeError("openssl x509 failed: " + concise_openssl_error(proc.stderr, proc.stdout))
    return proc.stdout.decode("utf-8", errors="replace")


def openssl_x509_pubkey_der(cert_path: Path) -> bytes:
    pub_proc = run_cmd(["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"])
    if pub_proc.returncode != 0:
        raise RuntimeError("openssl x509 -pubkey failed: " + concise_openssl_error(pub_proc.stderr, pub_proc.stdout))
    der_proc = run_cmd(["openssl", "pkey", "-pubin", "-outform", "DER"], input_bytes=pub_proc.stdout)
    if der_proc.returncode != 0:
        raise RuntimeError("openssl pkey -pubin failed: " + concise_openssl_error(der_proc.stderr, der_proc.stdout))
    return der_proc.stdout


def openssl_pkey_pub_der(key_path: Path, passphrase: str | None = None) -> bytes:
    cmd = ["openssl", "pkey", "-in", str(key_path), "-pubout", "-outform", "DER"]
    cmd.extend(["-passin", f"pass:{passphrase or ''}"])
    proc = run_cmd(cmd)
    if proc.returncode != 0:
        raise RuntimeError(concise_openssl_error(proc.stderr, proc.stdout))
    return proc.stdout


def inspect_certificate_file(cert_path: Path, index: int = 1) -> dict[str, Any]:
    text = openssl_x509_from_file(cert_path, "-text")
    subject_raw = first_line(openssl_x509_from_file(cert_path, "-subject"))
    issuer_raw = first_line(openssl_x509_from_file(cert_path, "-issuer"))
    serial_raw = first_line(openssl_x509_from_file(cert_path, "-serial"))
    dates_raw = openssl_x509_from_file(cert_path, "-dates")
    sha256_raw = first_line(openssl_x509_from_file(cert_path, "-fingerprint", "-sha256"))
    sha1_raw = first_line(openssl_x509_from_file(cert_path, "-fingerprint", "-sha1"))
    pub_der = openssl_x509_pubkey_der(cert_path)
    dates: dict[str, str] = {}
    for line in dates_raw.splitlines():
        if line.startswith("notBefore="):
            dates["notBefore"] = parse_openssl_date(line) or line
        elif line.startswith("notAfter="):
            dates["notAfter"] = parse_openssl_date(line) or line
    subject = split_dn(subject_raw)
    issuer = split_dn(issuer_raw)
    return {
        "ok": True,
        "index": index,
        "commonName": cn_from_subject(subject),
        "subject": subject,
        "issuer": issuer,
        "serialNumber": serial_with_colons(serial_raw),
        "version": extract_version(text),
        "publicKey": extract_public_key(text),
        "signatureAlgorithm": extract_signature_algorithm(text),
        "isCA": "CA:TRUE" in text,
        "notBefore": dates.get("notBefore"),
        "notAfter": dates.get("notAfter"),
        "subjectAlternativeNames": parse_sans(text),
        "keyUsage": extension_values_split(text, "X509v3 Key Usage"),
        "extendedKeyUsage": extension_values_split(text, "X509v3 Extended Key Usage"),
        "fingerprints": {
            "sha256": sha256_raw.split("=", 1)[1].strip() if "=" in sha256_raw else None,
            "sha1": sha1_raw.split("=", 1)[1].strip() if "=" in sha1_raw else None,
        },
        "publicKeySha256": colon_hex(hashlib.sha256(pub_der).digest()),
    }


def key_is_probably_encrypted(data: bytes) -> bool:
    clean = clean_upload_bytes(data)
    head = clean[:4096].decode("utf-8", errors="ignore").upper()
    return "ENCRYPTED" in head or "PROC-TYPE: 4,ENCRYPTED" in head


def inspect_private_key_file(key_path: Path, data: bytes, passphrase: str | None = None) -> dict[str, Any]:
    encrypted_hint = key_is_probably_encrypted(data)
    try:
        pub_der = openssl_pkey_pub_der(key_path, passphrase)
    except Exception as exc:
        message = str(exc)
        encrypted = encrypted_hint or "encrypted" in message.lower() or "passphrase" in message.lower() or "encryptedprivatekeyinfo" in message.lower()
        hint = "This private key appears to be encrypted. Enter the key passphrase and inspect again." if encrypted and not passphrase else None
        return {"ok": False, "encrypted": encrypted, "passphraseProvided": bool(passphrase), "error": message, "hint": hint}
    text_cmd = ["openssl", "pkey", "-in", str(key_path), "-noout", "-text", "-passin", f"pass:{passphrase or ''}"]
    proc = subprocess.run(text_cmd, text=True, capture_output=True)
    text = proc.stdout if proc.returncode == 0 else ""
    key_type = "OpenSSL-supported private key"
    key_size = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Private-Key:"):
            key_type = "Private key"; key_size = s.split(":",1)[1].strip(); break
        if s.startswith("ASN1 OID:"):
            key_type = s.split(":",1)[1].strip()
    if not key_size:
        pub_cmd = ["openssl", "pkey", "-in", str(key_path), "-pubout", "-text", "-noout", "-passin", f"pass:{passphrase or ''}"]
        pub_proc = subprocess.run(pub_cmd, text=True, capture_output=True)
        for line in pub_proc.stdout.splitlines():
            s = line.strip()
            if s.startswith("Public-Key:"):
                key_size = s.split(":",1)[1].strip(); break
    return {"ok": True, "encrypted": encrypted_hint or bool(passphrase), "passphraseProvided": bool(passphrase), "keyType": key_type, "keySize": key_size, "publicKeySha256": colon_hex(hashlib.sha256(pub_der).digest())}


def parse_multipart_form(body: bytes, content_type: str) -> dict[str, dict[str, Any]]:
    import email
    from email import policy
    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
    msg = email.message_from_bytes(header + body, policy=policy.default)
    if not msg.is_multipart():
        raise ValueError("Upload body was not parsed as multipart/form-data")
    fields: dict[str, dict[str, Any]] = {}
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        fields[name] = {"filename": filename, "contentType": part.get_content_type() or "application/octet-stream", "data": payload, "text": payload.decode("utf-8", errors="replace")}
    return fields


def inspect_uploads(fields: dict[str, dict[str, Any]]) -> dict[str, Any]:
    cert_field = fields.get("certificate")
    key_field = fields.get("privateKey")
    passphrase = fields.get("passphrase", {}).get("text", "").strip() or None
    result: dict[str, Any] = {
        "ok": True,
        "generatedAt": now_iso(),
        "uploads": {
            "certificateFileName": cert_field.get("filename") if cert_field else None,
            "keyFileName": key_field.get("filename") if key_field else None,
            "certificateBytes": len(cert_field.get("data", b"")) if cert_field else 0,
            "keyBytes": len(key_field.get("data", b"")) if key_field else 0,
            "passphraseProvided": bool(passphrase),
        },
        "certificates": [],
        "key": None,
        "match": None,
        "warnings": [],
    }
    first_cert_pub_sha: str | None = None
    key_pub_sha: str | None = None
    with tempfile.TemporaryDirectory(prefix="certdash-upload-") as td:
        tmp = Path(td)
        if cert_field and cert_field.get("data"):
            cert_data = clean_upload_bytes(cert_field["data"])
            blocks = split_pem_certificates(cert_data)
            cert_files: list[Path] = []
            if blocks:
                for idx, block in enumerate(blocks, 1):
                    p = tmp / f"uploaded-cert-{idx}.pem"; p.write_bytes(block); cert_files.append(p)
            elif looks_like_der_certificate(cert_data):
                p = tmp / "uploaded-cert-1.der"; p.write_bytes(cert_data); cert_files.append(p)
            else:
                p = tmp / "uploaded-cert-1.pem"; p.write_bytes(cert_data)
                try:
                    openssl_x509_from_file(p, "-subject")
                    cert_files.append(p)
                    result["warnings"].append("Certificate did not match simple PEM/DER detection, but OpenSSL parsed it successfully.")
                except Exception as exc:
                    result["warnings"].append(f"Certificate upload could not be parsed as PEM or DER: {exc}")
            for idx, cert_path in enumerate(cert_files, 1):
                try:
                    info = inspect_certificate_file(cert_path, idx)
                    result["certificates"].append(info)
                    if idx == 1:
                        first_cert_pub_sha = info.get("publicKeySha256")
                except Exception as exc:
                    result["certificates"].append({"ok": False, "index": idx, "error": str(exc)})
                    result["ok"] = False
        if key_field and key_field.get("data"):
            key_data = clean_upload_bytes(key_field["data"])
            key_path = tmp / "uploaded-key.pem"; key_path.write_bytes(key_data)
            key_info = inspect_private_key_file(key_path, key_data, passphrase)
            result["key"] = key_info
            key_pub_sha = key_info.get("publicKeySha256") if key_info.get("ok") else None
            if not key_info.get("ok"):
                result["ok"] = False
        if cert_field and key_field:
            compared = bool(first_cert_pub_sha and key_pub_sha)
            result["match"] = {
                "compared": compared,
                "matches": (first_cert_pub_sha == key_pub_sha) if compared else None,
                "certificatePublicKeySha256": first_cert_pub_sha,
                "privateKeyPublicKeySha256": key_pub_sha,
                "reason": "public key hashes compared" if compared else "unable to compare; certificate or key public key hash unavailable",
            }
    return result


ISSUED_DIR: Path | None = None
BROWSE_USER = "admin"
BROWSE_PASSWORD: str | None = None
BROWSE_MIN_PASSWORD_LEN = 12
BROWSE_FAIL_LIMIT = 10
BROWSE_FAIL_WINDOW_SECONDS = 300.0
BROWSE_FAILURES: dict[str, list[float]] = {}
BROWSE_LOCK = threading.Lock()
# Directory and file names must look like what cert_gen.sh produces: no leading dot,
# no slashes, no "..". Anything else is never listed and never served.
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")


def browse_enabled() -> bool:
    return ISSUED_DIR is not None and bool(BROWSE_PASSWORD)


def browse_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    with BROWSE_LOCK:
        recent = [t for t in BROWSE_FAILURES.get(ip, []) if now - t < BROWSE_FAIL_WINDOW_SECONDS]
        BROWSE_FAILURES[ip] = recent
        return len(recent) >= BROWSE_FAIL_LIMIT


def browse_record_failure(ip: str) -> None:
    with BROWSE_LOCK:
        BROWSE_FAILURES.setdefault(ip, []).append(time.monotonic())


def browse_clear_failures(ip: str) -> None:
    with BROWSE_LOCK:
        BROWSE_FAILURES.pop(ip, None)


def safe_issued_file(host: str, name: str) -> Path | None:
    """Return the resolved path of issued/<host>/<name>, or None if it is not a plain file inside it."""
    if ISSUED_DIR is None or not SAFE_NAME_RE.match(host) or not SAFE_NAME_RE.match(name):
        return None
    host_dir = ISSUED_DIR / host
    candidate = host_dir / name
    try:
        if host_dir.is_symlink() or candidate.is_symlink():
            return None
        resolved = candidate.resolve(strict=True)
        root = host_dir.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not resolved.is_file() or not resolved.is_relative_to(root):
        return None
    return resolved


def issued_file_kind(name: str) -> tuple[str, bool]:
    """Return (human readable kind, is_sensitive)."""
    backup = ".backup-" in name
    if ".key.pem" in name:
        kind, sensitive = "private key", True
    elif name.endswith(".fullchain.pem"):
        kind, sensitive = "certificate + intermediate", False
    elif name.endswith(".chain.pem"):
        kind, sensitive = "CA chain (intermediate + root)", False
    elif name.endswith(".cert.pem"):
        kind, sensitive = "certificate", False
    elif name.endswith(".csr.pem"):
        kind, sensitive = "certificate request", False
    elif name.endswith(".cert.txt"):
        kind, sensitive = "certificate text dump", False
    elif ".openssl.cnf" in name:
        kind, sensitive = "OpenSSL config", False
    else:
        kind, sensitive = "other", False
    if backup:
        kind += " (backup)"
    return kind, sensitive


def issued_cert_summary(cert_path: Path) -> dict[str, Any]:
    out = openssl_x509_from_file(cert_path, "-enddate", "-subject", "-ext", "subjectAltName")
    not_after = None
    subject = ""
    for line in out.splitlines():
        if line.startswith("notAfter="):
            not_after = parse_openssl_date(line)
        elif line.startswith("subject="):
            subject = split_dn(line)
    return {
        "commonName": cn_from_subject(subject),
        "notAfter": not_after,
        "subjectAlternativeNames": parse_sans(out),
    }


def list_issued() -> list[dict[str, Any]]:
    hosts: list[dict[str, Any]] = []
    if ISSUED_DIR is None or not ISSUED_DIR.is_dir():
        return hosts

    for host_dir in sorted(ISSUED_DIR.iterdir(), key=lambda p: p.name):
        if host_dir.is_symlink() or not host_dir.is_dir() or not SAFE_NAME_RE.match(host_dir.name):
            continue

        files: list[dict[str, Any]] = []
        for f in sorted(host_dir.iterdir(), key=lambda p: p.name):
            if f.is_symlink() or not f.is_file() or not SAFE_NAME_RE.match(f.name):
                continue
            st = f.stat()
            kind, sensitive = issued_file_kind(f.name)
            files.append({
                "name": f.name,
                "kind": kind,
                "sensitive": sensitive,
                "size": st.st_size,
                "modified": dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            })

        if not files:
            continue

        entry: dict[str, Any] = {"name": host_dir.name, "files": files, "certificate": None}
        cert_path = host_dir / f"{host_dir.name}.cert.pem"
        if cert_path.is_file() and not cert_path.is_symlink():
            try:
                entry["certificate"] = issued_cert_summary(cert_path)
            except Exception as exc:
                entry["certificate"] = {"error": str(exc)}
        hosts.append(entry)

    return hosts


def zip_issued_host(host: str) -> bytes | None:
    if ISSUED_DIR is None or not SAFE_NAME_RE.match(host):
        return None
    host_dir = ISSUED_DIR / host
    if host_dir.is_symlink() or not host_dir.is_dir():
        return None

    buf = io.BytesIO()
    count = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(host_dir.iterdir(), key=lambda p: p.name):
            safe = safe_issued_file(host, f.name)
            if safe is None:
                continue
            zf.write(safe, arcname=f"{host}/{f.name}")
            count += 1
    return buf.getvalue() if count else None


PKI_DIR: Path | None = None
ISSUE_ENABLED = False
ISSUE_LOCK = threading.Lock()
ISSUE_TIMEOUT_SECONDS = 120
ISSUE_MAX_ITEMS = 20
ISSUE_MAX_OUTPUT_CHARS = 20000
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,250}[A-Za-z0-9])?$")


def issue_enabled() -> bool:
    return ISSUE_ENABLED and PKI_DIR is not None and browse_enabled()


def valid_hostname(value: str) -> bool:
    return bool(HOSTNAME_RE.match(value)) and ".." not in value


def split_items(value: Any, label: str) -> tuple[list[str], str | None]:
    if value is None or value == "":
        return [], None
    if isinstance(value, str):
        items = [item for item in re.split(r"[\s,;]+", value) if item]
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        items = [item.strip() for item in value if item.strip()]
    else:
        return [], f"{label} must be text or a list of text."
    if len(items) > ISSUE_MAX_ITEMS:
        return [], f"Too many {label} (maximum {ISSUE_MAX_ITEMS})."
    return items, None


def parse_issue_request(payload: Any) -> tuple[list[str], str | None]:
    """Validate the JSON body and build the cert_gen.sh argument list.

    Nothing from the request is ever interpreted by a shell: every value is validated
    here and passed as a separate argv element. Options such as --editor are not exposed.
    """
    if not isinstance(payload, dict):
        return [], "Request body must be a JSON object."

    host = payload.get("hostname")
    if not isinstance(host, str) or not valid_hostname(host.strip()):
        return [], "Hostname may contain only letters, digits, dots and hyphens, and must start and end with a letter or digit."
    host = host.strip()

    args = [host, "--no-edit"]

    domain = payload.get("domain")
    if domain is not None and domain != "":
        if not isinstance(domain, str) or not valid_hostname(domain.strip()):
            return [], "Domain override is not a valid domain name."
        args += ["--domain", domain.strip()]

    ips, error = split_items(payload.get("ips"), "IP addresses")
    if error:
        return [], error
    clean_ips: list[str] = []
    for item in ips:
        try:
            if "%" in item:
                raise ValueError("scope ids are not supported")
            ip = str(ipaddress.ip_address(item))
        except ValueError:
            return [], f"'{item[:60]}' is not a valid IP address."
        if ip not in clean_ips:
            clean_ips.append(ip)
    for ip in clean_ips:
        args += ["--ip", ip]

    names, error = split_items(payload.get("dns"), "DNS names")
    if error:
        return [], error
    for name in dict.fromkeys(names):
        if not valid_hostname(name):
            return [], f"'{name[:60]}' is not a valid DNS name (wildcards are not supported)."
        args += ["--dns", name]

    days = payload.get("days")
    if days is not None and days != "":
        if isinstance(days, int) and not isinstance(days, bool):
            days_value = days
        elif isinstance(days, str) and days.strip().isdigit():
            days_value = int(days.strip())
        else:
            return [], "Valid-for days must be a whole number."
        if not 1 <= days_value <= 3650:
            return [], "Valid-for days must be between 1 and 3650."
        args += ["--days", str(days_value)]

    for key, option in (("force", "--force"), ("regenConfig", "--regen-config"), ("regenKey", "--regen-key")):
        value = payload.get(key)
        if value is not None and not isinstance(value, bool):
            return [], f"{key} must be true or false."
        if value is True:
            args.append(option)

    return args, None


def run_cert_gen(args: list[str]) -> dict[str, Any]:
    if PKI_DIR is None:
        return {"ok": False, "error": "PKI directory is not configured.", "generatedAt": now_iso()}

    # cert_gen.sh is not safe to run concurrently (serial file, shared output folders).
    if not ISSUE_LOCK.acquire(timeout=5):
        return {"ok": False, "error": "Another certificate is being generated. Try again in a moment.", "generatedAt": now_iso()}

    try:
        env = {key: value for key, value in os.environ.items() if key != "PKI_BROWSE_PASSWORD"}
        proc = subprocess.run(
            ["bash", str(PKI_DIR / "cert_gen.sh"), *args],
            cwd=str(PKI_DIR),
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=ISSUE_TIMEOUT_SECONDS,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"cert_gen.sh did not finish within {ISSUE_TIMEOUT_SECONDS} seconds.", "generatedAt": now_iso()}
    except Exception as exc:
        return {"ok": False, "error": f"Could not run cert_gen.sh: {exc}", "generatedAt": now_iso()}
    finally:
        ISSUE_LOCK.release()

    if len(output) > ISSUE_MAX_OUTPUT_CHARS:
        output = output[:ISSUE_MAX_OUTPUT_CHARS] + "\n... (output truncated)"

    match = re.search(r"^\[INFO\] Target FQDN: (\S+)", output, flags=re.MULTILINE)
    return {
        "ok": exit_code == 0,
        "exitCode": exit_code,
        "fqdn": match.group(1) if match else None,
        "arguments": args,
        "output": output,
        "generatedAt": now_iso(),
    }


class CertDashboardHandler(http.server.SimpleHTTPRequestHandler):
    server_version = "CertDashboardHTTP/1.1"

    def end_headers(self) -> None:
        self.send_header("X-Cert-Dashboard", "true")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[%s] %s - %s\n" % (
            dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            self.client_address[0],
            fmt % args,
        ))

    def send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        raw = json.dumps(payload, indent=2, ensure_ascii=False, default=json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header(
            "Access-Control-Expose-Headers",
            "Content-Type, Content-Length, Cache-Control, X-Cert-Dashboard, X-Content-Type-Options, Server, Date",
        )
        self.end_headers()
        self.wfile.write(raw)


    def do_POST(self) -> None:
        clean_path = self.path.split("?", 1)[0]
        if clean_path == "/__issue.json":
            self.handle_issue()
            return
        if clean_path == "/__upload_inspect.json":
            self.handle_upload_inspect()
            return
        self.send_json({"ok": False, "error": f"Unsupported POST endpoint: {clean_path}", "generatedAt": now_iso()}, status=404)

    def handle_upload_inspect(self) -> None:
        content_type = self.headers.get("Content-Type", "")
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json({"ok": False, "error": "Invalid Content-Length", "generatedAt": now_iso()}, status=400)
            return
        if content_length <= 0:
            self.send_json({"ok": False, "error": "Empty upload body", "generatedAt": now_iso()}, status=400)
            return
        if content_length > MAX_UPLOAD_BYTES:
            self.send_json({"ok": False, "error": f"Upload too large. Limit is {MAX_UPLOAD_BYTES} bytes.", "generatedAt": now_iso()}, status=413)
            return
        if "multipart/form-data" not in content_type:
            self.send_json({"ok": False, "error": "Expected multipart/form-data upload", "generatedAt": now_iso()}, status=400)
            return
        try:
            body = self.rfile.read(content_length)
            fields = parse_multipart_form(body, content_type)
            self.send_json(inspect_uploads(fields), status=200)
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc), "generatedAt": now_iso()}, status=200)

    def do_OPTIONS(self) -> None:
        if self.path.split("?", 1)[0].startswith("/__issue"):
            # Same-origin only: never approve a cross-origin preflight for the issue/download endpoints.
            self.send_response(204)
            self.end_headers()
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Accept, Content-Type, X-Cert-Dashboard, X-Cert-Dashboard-Upload, X-Demo-Sent-By, X-Demo-Purpose, X-Demo-Probe",
        )
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    # --- issued certificate browser -------------------------------------------------
    # Deliberately NO CORS headers on these responses: only this origin's own page may use them.

    def send_browse_json(self, payload: dict[str, Any], status: int = 200, challenge: bool = False) -> None:
        raw = json.dumps(payload, indent=2, ensure_ascii=False, default=json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        if challenge:
            self.send_header("WWW-Authenticate", 'Basic realm="PKI issued certificates", charset="UTF-8"')
        self.end_headers()
        self.wfile.write(raw)

    def send_browse_error(self, status: int, message: str, challenge: bool = False) -> None:
        self.send_browse_json({"ok": False, "error": message, "generatedAt": now_iso()}, status=status, challenge=challenge)

    def send_browse_file(self, data: bytes, filename: str, content_type: str = "application/octet-stream") -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def browse_authorize(self) -> bool:
        """True if this request may use the issued-certificate browser; otherwise the error response was already sent."""
        if not browse_enabled():
            self.send_browse_error(404, "Issued-certificate browser is disabled. Set PKI_BROWSE_PASSWORD (at least 12 characters) to enable it.")
            return False

        if not isinstance(self.request, ssl.SSLSocket):
            self.send_browse_error(403, "HTTPS required: private keys and the password are never sent over plain HTTP.")
            return False

        ip = self.client_address[0]
        if browse_rate_limited(ip):
            self.send_browse_error(429, "Too many failed attempts from this address. Try again in a few minutes.")
            return False

        header = self.headers.get("Authorization", "")
        if header.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
                user, _, password = decoded.partition(":")
            except Exception:
                user, password = "", ""

            user_ok = hmac.compare_digest(user.encode("utf-8"), BROWSE_USER.encode("utf-8"))
            pass_ok = hmac.compare_digest(password.encode("utf-8"), (BROWSE_PASSWORD or "").encode("utf-8"))
            if user_ok and pass_ok:
                browse_clear_failures(ip)
                return True

            browse_record_failure(ip)
            log("WARN", f"Failed issued-browser login from {ip}")
            time.sleep(1.0)

        self.send_browse_error(401, "Authentication required.", challenge=True)
        return False

    def handle_issue(self) -> None:
        if not self.browse_authorize():
            return
        if not issue_enabled():
            self.send_browse_error(404, "Certificate generation from the web is disabled. Start the container with PKI_WEB_ISSUE=true to enable it.")
            return

        # CSRF defence. Browsers attach cached Basic credentials to cross-site requests (for example
        # a hidden form on another website), so insist on a JSON body (a cross-site form cannot send
        # one) and on same-origin metadata whenever the browser supplies it.
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.send_browse_error(415, "Expected Content-Type: application/json.")
            return
        origin = self.headers.get("Origin")
        if origin and origin != f"https://{self.headers.get('Host', '')}":
            self.send_browse_error(403, "Cross-origin request refused.")
            return
        if self.headers.get("Sec-Fetch-Site", "same-origin") != "same-origin":
            self.send_browse_error(403, "Cross-site request refused.")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 16384:
            self.send_browse_error(400, "Invalid request size.")
            return

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self.send_browse_error(400, "Request body is not valid JSON.")
            return

        args, error = parse_issue_request(payload)
        if error:
            self.send_browse_error(400, error)
            return

        log("INFO", f"Issue request from {self.client_address[0]}: cert_gen.sh {' '.join(args)}")
        self.send_browse_json(run_cert_gen(args))

    def handle_issued_list(self) -> None:
        if not self.browse_authorize():
            return
        self.send_browse_json({"ok": True, "generatedAt": now_iso(), "hosts": list_issued()})

    def handle_issued_download(self, clean_path: str) -> None:
        if not self.browse_authorize():
            return

        parts = urllib.parse.unquote(clean_path[len("/__issued/"):]).split("/")

        if len(parts) == 1 and parts[0].endswith(".zip"):
            host = parts[0][:-4]
            data = zip_issued_host(host)
            if data is None:
                self.send_browse_error(404, "Not found.")
                return
            log("INFO", f"Issued download: {host}.zip by {self.client_address[0]}")
            self.send_browse_file(data, f"{host}.zip", "application/zip")
            return

        if len(parts) == 2:
            file_path = safe_issued_file(parts[0], parts[1])
            if file_path is None:
                self.send_browse_error(404, "Not found.")
                return
            log("INFO", f"Issued download: {parts[0]}/{parts[1]} by {self.client_address[0]}")
            self.send_browse_file(file_path.read_bytes(), parts[1])
            return

        self.send_browse_error(404, "Not found.")

    def do_GET(self) -> None:
        clean_path = self.path.split("?", 1)[0]

        if clean_path == "/__issued.json":
            self.handle_issued_list()
            return

        if clean_path.startswith("/__issued/"):
            self.handle_issued_download(clean_path)
            return

        if clean_path == "/__certinfo.json":
            payload = certificate_json()
            # Always HTTP 200 so curl/browser always show the JSON diagnostic body.
            self.send_json(payload, status=200)
            return

        if clean_path == "/__headers.json":
            self.send_json(self.headers_json(), status=200)
            return

        if clean_path == "/__tls.json":
            self.send_json(self.tls_json(), status=200)
            return

        if clean_path == "/__health.json":
            self.send_json(self.health_json(), status=200)
            return

        if clean_path == "/__upload_inspect.json":
            self.send_json({
                "ok": True,
                "endpoint": "/__upload_inspect.json",
                "method": "POST",
                "description": "Upload certificate and/or private key files using multipart/form-data fields named certificate and privateKey.",
                "maxUploadBytes": MAX_UPLOAD_BYTES,
                "generatedAt": now_iso(),
            }, status=200)
            return

        super().do_GET()

    def health_json(self) -> dict[str, Any]:
        return {
            "ok": True,
            "generatedAt": now_iso(),
            "startedAt": STARTED_AT.isoformat().replace("+00:00", "Z"),
            "server": self.server_version,
            "opensslFound": openssl_available(),
            "certConfigured": CERT_PATH is not None,
            "keyConfigured": KEY_PATH is not None,
            "certPath": str(CERT_PATH) if CERT_PATH else None,
            "keyPath": str(KEY_PATH) if KEY_PATH else None,
            "certExists": CERT_PATH.exists() if CERT_PATH else False,
            "keyExists": KEY_PATH.exists() if KEY_PATH else False,
            "tlsForThisRequest": isinstance(self.request, ssl.SSLSocket),
            "tlsEndpoint": "/__tls.json",
            "uploadInspectorEndpoint": "/__upload_inspect.json",
            "maxUploadBytes": MAX_UPLOAD_BYTES,
            "minimumTlsVersion": TLS_MIN_VERSION_NAME,
            "issuedBrowserEnabled": browse_enabled(),
            "certIssueEnabled": issue_enabled(),
        }


    def tls_json(self) -> dict[str, Any]:
        tls_enabled = isinstance(self.request, ssl.SSLSocket)

        base: dict[str, Any] = {
            "ok": True,
            "generatedAt": now_iso(),
            "note": "TLS information is based on the current request socket. Open this page over HTTPS to populate negotiated TLS values.",
            "request": {
                "method": self.command,
                "path": self.path,
                "protocolVersion": self.request_version,
            },
            "remote": {
                "address": self.client_address[0],
                "port": self.client_address[1],
            },
            "local": {
                "address": None,
                "port": None,
            },
            "tls": {
                "enabled": tls_enabled,
                "protocolVersion": None,
                "cipher": None,
                "compression": None,
                "alpnProtocol": None,
                "npnProtocol": None,
                "sharedCiphers": [],
                "channelBinding": {
                    "available": False,
                    "length": None,
                    "sha256": None,
                },
            },
            "clientCertificate": {
                "present": False,
            },
            "runtime": {
                "pythonSsl": getattr(ssl, "__name__", "ssl"),
                "opensslVersion": ssl.OPENSSL_VERSION,
                "opensslVersionInfo": ".".join(str(x) for x in ssl.OPENSSL_VERSION_INFO),
                "hasTlsVersionEnum": hasattr(ssl, "TLSVersion"),
                "hasAlpn": ssl.HAS_ALPN,
                "hasNpn": getattr(ssl, "HAS_NPN", False),
                "hasSni": ssl.HAS_SNI,
                "defaultVerifyPaths": {
                    "cafile": ssl.get_default_verify_paths().cafile,
                    "capath": ssl.get_default_verify_paths().capath,
                    "opensslCafile": ssl.get_default_verify_paths().openssl_cafile,
                    "opensslCapath": ssl.get_default_verify_paths().openssl_capath,
                },
            },
            "serverConfig": {
                "certPath": str(CERT_PATH) if CERT_PATH else None,
                "keyPath": str(KEY_PATH) if KEY_PATH else None,
                "certExists": CERT_PATH.exists() if CERT_PATH else False,
                "keyExists": KEY_PATH.exists() if KEY_PATH else False,
                "minimumTlsVersion": TLS_MIN_VERSION_NAME,
                "sniCallbackUsed": SNI_CALLBACK_USED,
            },
            "limitations": [
                "Python's standard library does not expose the full ClientHello or browser TLS trust decision.",
                "Use openssl s_client, testssl.sh, nmap ssl-enum-ciphers, or Wireshark for full external TLS auditing.",
            ],
        }

        local = safe_call(lambda: self.request.getsockname(), None)
        if isinstance(local, tuple) and len(local) >= 2:
            base["local"] = {
                "address": local[0],
                "port": local[1],
            }

        if not tls_enabled:
            base["note"] = "This request is HTTP, not HTTPS. TLS session details are not available."
            return base

        sock = self.request

        base["tls"].update({
            "protocolVersion": safe_call(lambda: sock.version(), None),
            "cipher": cipher_tuple_to_dict(safe_call(lambda: sock.cipher(), None)),
            "compression": safe_call(lambda: sock.compression(), None),
            "alpnProtocol": safe_call(lambda: sock.selected_alpn_protocol(), None),
            "npnProtocol": safe_call(lambda: sock.selected_npn_protocol(), None),
            "sharedCiphers": shared_ciphers_to_list(safe_call(lambda: sock.shared_ciphers(), None)),
        })

        channel_binding = safe_call(lambda: sock.get_channel_binding("tls-unique"), None)
        if channel_binding:
            base["tls"]["channelBinding"] = {
                "available": True,
                "length": len(channel_binding),
                "sha256": colon_hex(hashlib.sha256(channel_binding).digest()),
            }

        base["clientCertificate"] = peer_cert_summary(sock)

        return base


    def headers_json(self) -> dict[str, Any]:
        tls_enabled = isinstance(self.request, ssl.SSLSocket)

        return {
            "ok": True,
            "generatedAt": now_iso(),
            "request": {
                "method": self.command,
                "path": self.path,
                "protocolVersion": self.request_version,
                "clientAddress": self.client_address[0],
                "clientPort": self.client_address[1],
                "tls": tls_enabled,
                "serverName": getattr(self.server, "server_name", ""),
                "serverPort": getattr(self.server, "server_port", ""),
            },
            "requestHeaders": {key: value for key, value in self.headers.items()},
            "responseHeadersPlanned": {
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
                "X-Cert-Dashboard": "true",
                "X-Content-Type-Options": "nosniff",
                "Access-Control-Allow-Origin": "*",
            },
        }


def serve(host: str, port: int, directory: Path, use_https: bool) -> None:
    handler = partial(CertDashboardHandler, directory=str(directory))
    httpd = http.server.ThreadingHTTPServer((host, port), handler)

    scheme = "http"
    if use_https:
        if CERT_PATH is None or KEY_PATH is None:
            raise SystemExit("HTTPS requires --cert and --key.")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=str(CERT_PATH), keyfile=str(KEY_PATH))
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    log("INFO", f"Serving {directory} at {scheme}://{host}:{port}/")
    log("INFO", f"Health endpoint:      {scheme}://{host}:{port}/__health.json")
    log("INFO", f"Certificate endpoint: {scheme}://{host}:{port}/__certinfo.json")
    log("INFO", f"TLS endpoint:         {scheme}://{host}:{port}/__tls.json")
    log("INFO", f"Header endpoint:      {scheme}://{host}:{port}/__headers.json")
    log("INFO", f"Upload inspector:     {scheme}://{host}:{port}/__upload_inspect.json")
    httpd.serve_forever()


def main() -> None:
    global CERT_PATH, KEY_PATH, ISSUED_DIR, BROWSE_USER, BROWSE_PASSWORD, PKI_DIR, ISSUE_ENABLED

    parser = argparse.ArgumentParser(description="Static web server with robust certificate/header dashboard endpoints.")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address. Default: 0.0.0.0")
    parser.add_argument("--directory", default="./www", help="Directory to serve. Default: ./www")
    parser.add_argument("--http-port", type=int, default=8080, help="HTTP port. Use 0 to disable. Default: 8080")
    parser.add_argument("--https-port", type=int, default=0, help="HTTPS port. Use 0 to disable. Default: 0")
    parser.add_argument("--cert", help="PEM certificate file. May be a single cert or a chain file. First cert is displayed.")
    parser.add_argument("--key", help="PEM private key file used by HTTPS.")
    parser.add_argument("--issued-dir", help="Directory of issued certificates to expose through the authenticated browser. Also requires the PKI_BROWSE_PASSWORD environment variable and an HTTPS listener.")
    parser.add_argument("--browse-user", default=os.environ.get("PKI_BROWSE_USER", "admin"), help="User name for the issued-certificate browser. Default: admin")
    parser.add_argument("--pki-dir", help="Directory containing cert_gen.sh. With PKI_WEB_ISSUE=true this enables certificate generation from the web.")
    args = parser.parse_args()

    directory = Path(args.directory).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)

    if args.cert:
        CERT_PATH = Path(args.cert).expanduser().resolve()
    if args.key:
        KEY_PATH = Path(args.key).expanduser().resolve()

    if args.issued_dir:
        ISSUED_DIR = Path(args.issued_dir).expanduser().resolve()
        BROWSE_USER = args.browse_user or "admin"
        BROWSE_PASSWORD = os.environ.get("PKI_BROWSE_PASSWORD") or None
        if not BROWSE_PASSWORD:
            log("INFO", "Issued-certificate browser: DISABLED (PKI_BROWSE_PASSWORD not set)")
        elif len(BROWSE_PASSWORD) < BROWSE_MIN_PASSWORD_LEN:
            log("WARN", f"Issued-certificate browser: DISABLED (PKI_BROWSE_PASSWORD must be at least {BROWSE_MIN_PASSWORD_LEN} characters)")
            BROWSE_PASSWORD = None
        elif not args.https_port or CERT_PATH is None or KEY_PATH is None:
            log("WARN", "Issued-certificate browser: DISABLED (needs an HTTPS listener; keys are never served over HTTP)")
            BROWSE_PASSWORD = None
        else:
            log("INFO", f"Issued-certificate browser: enabled for user '{BROWSE_USER}' over HTTPS, directory {ISSUED_DIR}")

    if args.pki_dir:
        pki_dir = Path(args.pki_dir).expanduser().resolve()
        if (pki_dir / "cert_gen.sh").is_file():
            PKI_DIR = pki_dir
        else:
            log("WARN", f"--pki-dir {pki_dir} contains no cert_gen.sh; certificate generation from the web is unavailable")

    if os.environ.get("PKI_WEB_ISSUE", "").strip().lower() in ("1", "true", "yes", "on"):
        if PKI_DIR is None:
            log("WARN", "Certificate generation from the web: DISABLED (no --pki-dir containing cert_gen.sh)")
        elif not browse_enabled():
            log("WARN", "Certificate generation from the web: DISABLED (needs the issued-certificate browser: PKI_BROWSE_PASSWORD and HTTPS)")
        else:
            ISSUE_ENABLED = True
            log("INFO", "Certificate generation from the web: ENABLED (anyone with the browse password can issue certificates your clients will trust)")
    else:
        log("INFO", "Certificate generation from the web: disabled (set PKI_WEB_ISSUE=true to enable)")

    log("INFO", f"Document root: {directory}")
    log("INFO", f"OpenSSL found: {openssl_available()}")
    log("INFO", f"Configured cert: {CERT_PATH if CERT_PATH else '(none)'}")
    log("INFO", f"Configured key:  {KEY_PATH if KEY_PATH else '(none)'}")

    threads: list[threading.Thread] = []

    if args.http_port:
        t = threading.Thread(target=serve, args=(args.host, args.http_port, directory, False), daemon=True)
        t.start()
        threads.append(t)

    if args.https_port:
        if CERT_PATH is None or KEY_PATH is None:
            log("WARN", "HTTPS port was requested but --cert and/or --key is missing; skipping HTTPS listener.")
        else:
            t = threading.Thread(target=serve, args=(args.host, args.https_port, directory, True), daemon=True)
            t.start()
            threads.append(t)

    if not threads:
        raise SystemExit("Nothing to serve. Enable --http-port or --https-port.")

    log("INFO", "Press Ctrl+C to stop.")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        log("INFO", "Stopped.")


if __name__ == "__main__":
    main()
