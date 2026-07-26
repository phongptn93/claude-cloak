"""
Generate a local root CA + a forged leaf certificate for api.anthropic.com.

TEST MODE ONLY — feeds proxy.py's optional MITM listener (MITM_ENABLED=true),
which lets a client running Claude Code with ANTHROPIC_BASE_URL *unset* (so
Remote Control stays enabled) still be routed through the cloak, via a
hosts-file redirect + this forged cert.

certs/rootCA.key is the single most sensitive file this script produces:
anyone holding it can forge a trusted certificate for ANY domain on every
machine where certs/rootCA.crt is installed as a trusted root — not just
api.anthropic.com. Never commit it, never copy it off this server, and
delete it immediately if you stop using MITM mode.

Whether Claude Code actually accepts this forged leaf (vs. pinning the real
api.anthropic.com certificate) is NOT verified by this script — that can
only be confirmed by installing rootCA.crt + the hosts-file entry on a real
client and trying Remote Control there.
"""
import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
CA_KEY_PATH = os.path.join(CERTS_DIR, "rootCA.key")
CA_CERT_PATH = os.path.join(CERTS_DIR, "rootCA.crt")
LEAF_KEY_PATH = os.path.join(CERTS_DIR, "api.anthropic.com.key")
LEAF_CERT_PATH = os.path.join(CERTS_DIR, "api.anthropic.com.crt")

TARGET_HOSTNAME = "api.anthropic.com"


def _write_key(path, key):
    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(path, 0o600)


def _write_cert(path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _load_or_create_ca():
    if os.path.isfile(CA_KEY_PATH) and os.path.isfile(CA_CERT_PATH):
        with open(CA_KEY_PATH, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        print(f"[reuse] existing root CA: {CA_CERT_PATH}")
        return ca_key, ca_cert

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Claude Cloak Test Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Claude Cloak (local test only, do not distribute)"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_key(CA_KEY_PATH, ca_key)
    _write_cert(CA_CERT_PATH, ca_cert)
    print(f"[new] generated root CA: {CA_CERT_PATH}")
    return ca_key, ca_cert


def generate():
    os.makedirs(CERTS_DIR, exist_ok=True)
    ca_key, ca_cert = _load_or_create_ca()

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, TARGET_HOSTNAME)])
    now = datetime.datetime.now(datetime.timezone.utc)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(TARGET_HOSTNAME)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                key_cert_sign=False,
                crl_sign=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_key(LEAF_KEY_PATH, leaf_key)
    _write_cert(LEAF_CERT_PATH, leaf_cert)
    print(f"[new] generated leaf cert for {TARGET_HOSTNAME}: {LEAF_CERT_PATH}")

    print()
    print("Next steps (TEST MODE — verify before relying on this):")
    print(f"  1. Install the root CA as trusted on the CLIENT machine (admin/elevated shell):")
    print(f"       certutil -addstore -f \"ROOT\" \"{CA_CERT_PATH}\"")
    print(f"  2. Add a hosts-file entry on that client pointing the real domain at this server:")
    print(f"       <this-server-ip>   {TARGET_HOSTNAME}")
    print(f"     (Windows: C:\\Windows\\System32\\drivers\\etc\\hosts, needs admin to edit)")
    print(f"  3. On this server, set in .env: MITM_ENABLED=true, MITM_PORT=443")
    print(f"     (443 is required for real use — the hosts file only redirects the IP,")
    print(f"      not the port, and HTTPS clients default to 443)")
    print(f"  4. On the client, make sure ANTHROPIC_BASE_URL is UNSET (Remote Control")
    print(f"     disables itself otherwise), then start Claude Code and try Remote Control.")
    print()
    print("  This does NOT prove Claude Code will accept the forged cert — only a real")
    print("  client + real Remote Control attempt can confirm that.")


if __name__ == "__main__":
    if sys.version_info < (3, 9):
        print("Python 3.9+ required (uses datetime.timezone.utc-aware timestamps).")
        sys.exit(1)
    generate()
