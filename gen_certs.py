from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import os

# Create certs directory if it doesn't exist
if not os.path.exists("certs"):
    os.makedirs("certs")

# Generate private key
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)

# Generate a self-signed certificate
subject = issuer = x509.Name([
    x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Sentinel-X"),
    x509.NameAttribute(x509.NameOID.COMMON_NAME, u"localhost"),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
    critical=False,
).sign(key, hashes.SHA256(), default_backend())

# Write key.pem
with open("certs/key.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Write cert.pem
with open("certs/cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("Successfully generated certs/key.pem and certs/cert.pem")