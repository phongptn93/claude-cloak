"""
Generate a local TLS certificate chain so Claude Cloak can run in
TRANSPARENT_MODE — terminating TLS for `api.anthropic.com` on your own machine.

Why: Claude Code v2.1.196+ disables Remote Control whenever `ANTHROPIC_BASE_URL`
points anywhere other than `api.anthropic.com`. Transparent mode keeps that base
URL intact (a hosts entry sends the traffic to the local proxy instead), which
means the proxy has to present a certificate that the Claude Code (Node) process
will trust for the hostname `api.anthropic.com`.

This script mints:
  certs/ca.crt                  — local CA (trust anchor). Point NODE_EXTRA_CA_CERTS here.
  certs/ca.key                  — local CA private key (keep it local, git-ignored).
  certs/api.anthropic.com.crt   — leaf + CA chain. Use as TLS_CERT (uvicorn ssl_certfile).
  certs/api.anthropic.com.key   — leaf private key. Use as TLS_KEY (uvicorn ssl_keyfile).

Nothing here is secret to Anthropic — the CA is generated locally and only ever
trusted by your own machine. It does NOT let anyone impersonate Anthropic to
anyone else; it only lets *your* Claude Code trust *your* local proxy.

Usage:
  python gen_cert.py                       # writes into ./certs, hostname api.anthropic.com
  python gen_cert.py --out /path/to/certs  # custom output dir
  python gen_cert.py --host api.anthropic.com --days 3650
"""

import argparse
import datetime
import ipaddress
import os
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    print(
        "This script needs the 'cryptography' package:\n"
        "    pip install cryptography\n"
        "(it is listed in requirements.txt)",
        file=sys.stderr,
    )
    sys.exit(1)


def _write(path: str, data: bytes, secret: bool = False):
    with open(path, "wb") as f:
        f.write(data)
    if secret and os.name == "posix":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _key_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _cert_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def generate(out_dir: str, host: str, days: int) -> dict:
    os.makedirs(out_dir, exist_ok=True)

    now = datetime.datetime.utcnow()
    not_before = now - datetime.timedelta(days=1)
    not_after = now + datetime.timedelta(days=days)

    # ── Local CA ──────────────────────────────────────────────────────────
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Claude Cloak Local CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Claude Cloak"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                key_encipherment=False, content_commitment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # ── Leaf cert for the hostname ────────────────────────────────────────
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    san = [x509.DNSName(host)]
    # If someone passes an IP as the host, add it as an IP SAN too.
    try:
        san.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError:
        pass

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_crt_path = os.path.join(out_dir, "ca.crt")
    ca_key_path = os.path.join(out_dir, "ca.key")
    leaf_crt_path = os.path.join(out_dir, f"{host}.crt")
    leaf_key_path = os.path.join(out_dir, f"{host}.key")

    _write(ca_crt_path, _cert_pem(ca_cert))
    _write(ca_key_path, _key_pem(ca_key), secret=True)
    # Leaf certfile is a fullchain (leaf + CA) so uvicorn serves the chain.
    _write(leaf_crt_path, _cert_pem(leaf_cert) + _cert_pem(ca_cert))
    _write(leaf_key_path, _key_pem(leaf_key), secret=True)

    return {
        "ca_crt": ca_crt_path,
        "ca_key": ca_key_path,
        "leaf_crt": leaf_crt_path,
        "leaf_key": leaf_key_path,
    }


def main():
    parser = argparse.ArgumentParser(description="Generate local TLS certs for Claude Cloak transparent mode")
    parser.add_argument("--out", default=None, help="output directory (default: ./certs next to this script)")
    parser.add_argument("--host", default="api.anthropic.com", help="hostname to issue the leaf cert for")
    parser.add_argument("--days", type=int, default=3650, help="certificate validity in days")
    args = parser.parse_args()

    out_dir = args.out or os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
    paths = generate(out_dir, args.host, args.days)

    print("Generated local TLS chain:")
    print(f"  CA cert  (trust anchor) : {paths['ca_crt']}")
    print(f"  CA key                  : {paths['ca_key']}")
    print(f"  Leaf cert (fullchain)   : {paths['leaf_crt']}")
    print(f"  Leaf key                : {paths['leaf_key']}")
    print()
    print("Next steps for transparent / Remote-Control mode:")
    print(f"  1. TLS_CERT={paths['leaf_crt']}")
    print(f"  2. TLS_KEY={paths['leaf_key']}")
    print(f"  3. Trust the CA in Claude Code: set NODE_EXTRA_CA_CERTS={paths['ca_crt']}")
    print("  4. Add a hosts entry: 127.0.0.1 api.anthropic.com")
    print("  5. Leave ANTHROPIC_BASE_URL UNSET so Remote Control stays enabled.")


if __name__ == "__main__":
    main()
