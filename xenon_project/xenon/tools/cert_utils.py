import logging
import datetime
import secrets
import base64

# Cryptography library components
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519

logger = logging.getLogger(__name__)

def generate_self_signed_cert(common_name="xray.com", validity_days=3650):
    """
    Generates a self-signed RSA certificate and private key.
    Returns (cert_pem, key_pem) or (None, None) on error.
    """
    try:
        logger.debug(f"Generating self-signed certificate for CN: {common_name}")
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048, # Standard key size
            backend=default_backend()
        )

        # Create a subject/issuer name (same for self-signed)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"), # Default values
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SelfSignedOrg"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) # Mark as CA
        )

        certificate = cert_builder.sign(key, hashes.SHA256(), default_backend())

        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL, # PKCS1 format
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        logger.info(f"Successfully generated self-signed certificate for {common_name}")
        return cert_pem, key_pem

    except Exception as e:
        logger.error(f"Error generating self-signed certificate: {e}", exc_info=True)
        return None, None


def generate_reality_keypair():
    """
    Generates an X25519 key pair for Xray REALITY.
    Returns (private_key_b64, public_key_b64) or (None, None) on error.
    """
    try:
        logger.debug("Generating X25519 key pair for REALITY.")
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize keys to raw bytes
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw, # Use Raw format for X25519
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw # Use Raw format for X25519
        )

        # Encode to URL-safe base64 (commonly used for REALITY keys)
        private_key_b64 = base64.urlsafe_b64encode(priv_bytes).rstrip(b'=').decode('utf-8')
        public_key_b64 = base64.urlsafe_b64encode(pub_bytes).rstrip(b'=').decode('utf-8')

        logger.info("Successfully generated REALITY key pair.")
        return private_key_b64, public_key_b64

    except Exception as e:
        logger.error(f"Error generating REALITY key pair: {e}", exc_info=True)
        return None, None


def generate_hex_short_ids(count=8, length_bytes=4):
    """
    Generates a list of random hex strings to be used as short IDs for REALITY.
    Returns a list of hex strings or an empty list on error.
    `length_bytes` determines the byte length before hex encoding (e.g., 4 bytes -> 8 hex chars).
    """
    if not (1 <= length_bytes <= 16): # Practical limits for short IDs
        logger.error(f"Invalid length_bytes for short ID generation: {length_bytes}. Must be between 1 and 16.")
        return []

    try:
        logger.debug(f"Generating {count} short IDs, each from {length_bytes} random bytes.")
        short_ids = [secrets.token_hex(length_bytes) for _ in range(count)]
        logger.info(f"Successfully generated {count} short IDs.")
        return short_ids
    except Exception as e:
        logger.error(f"Error generating short IDs: {e}", exc_info=True)
        return []

# Note: The generate_ss_password logic was moved to xenon/xray_config/inbounds.py (_generate_ss_password_logic)
# because it was directly used by the inbound form logic there.
# If it's needed as a general tool elsewhere, it could be moved here or to a dedicated ss_utils.py
# and then imported by both inbounds.py and tools/routes.py.
# For now, keeping it in inbounds.py to maintain closer proximity to its primary user.
```

**توضیحات:**

*   توابع `generate_self_signed_cert`، `generate_reality_keypair` و `generate_hex_short_ids` از `xenon.py` اصلی به این فایل منتقل شده‌اند.
*   از کتابخانه `cryptography` برای عملیات رمزنگاری استفاده شده است.
*   ثبت وقایع (Logging) برای اشکال‌زدایی و پیگیری خطاها اضافه شده است.
*   تابع تولید رمز عبور Shadowsocks (`generate_ss_password`) به دلیل استفاده مستقیم در منطق فرم ورودی‌ها، در `xenon/xray_config/inbounds.py` باقی مانده است. اگر نیاز به استفاده عمومی‌تر از آن باشد، می‌توان آن را به اینجا یا یک ماژول اختصاصی دیگر منتقل کرد.

در مرحله بعد، ماژول `xenon/tools/warp.py` (برای منطق Warp) و `xenon/tools/network_tests.py` (برای تست اتصال) و سپس `xenon/tools/routes.py` (برای مسیرهای این ابزارها) ایجاد خواهند شد.
