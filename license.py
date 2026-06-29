"""
License verification for TipOff.
The public key is embedded here — it is safe to be in open source.
Nobody can forge a valid signature without the private key.
"""
import base64, json
from dataclasses import dataclass, field
from datetime import date, timedelta
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_der_public_key
import binascii

# ── Embedded public key ────────────────────────────────────────────────────────
# Generated with keygen/generate_keypair.py.
# To rotate: run generate_keypair.py, paste the new hex here, rebuild.
_PUBLIC_KEY_HEX = "9f472ae1ac68312a8a429da71c53acdd4ada20ae624f51fe1787f076ad3ad872"

_GRACE_DAYS     = 7   # days after expiry before features are disabled
_WARN_DAYS      = 14  # days before expiry to show amber warning


class LicenseStatus(str, Enum):
    NONE          = "none"           # no key entered — free tier
    VALID         = "valid"
    EXPIRING_SOON = "expiring_soon"  # < 14 days remaining
    GRACE_PERIOD  = "grace_period"   # expired but within 7-day grace
    EXPIRED       = "expired"        # hard expired, features off
    INVALID       = "invalid"        # bad signature or tampered


@dataclass
class LicenseInfo:
    status:        LicenseStatus = LicenseStatus.NONE
    plan:          str           = "free"
    features:      set           = field(default_factory=set)
    email:         str           = ""
    issued:        date | None   = None
    expires:       date | None   = None
    days_remaining: int          = 0
    error:         str           = ""

    @property
    def active(self) -> bool:
        return self.status in (
            LicenseStatus.VALID,
            LicenseStatus.EXPIRING_SOON,
            LicenseStatus.GRACE_PERIOD,
        )

    def has_feature(self, feature: str) -> bool:
        return self.active and feature in self.features


def _get_public_key() -> Ed25519PublicKey:
    raw = bytes.fromhex(_PUBLIC_KEY_HEX)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    # Wrap raw bytes in SubjectPublicKeyInfo DER for Ed25519
    # DER prefix for Ed25519 public key (RFC 8410)
    der_prefix = bytes.fromhex("302a300506032b6570032100")
    return load_der_public_key(der_prefix + raw, backend=default_backend())


def verify_license_key(key_string: str, today: date | None = None) -> LicenseInfo:
    """Parse and verify a license key string. Returns a LicenseInfo."""
    today = today or date.today()

    if not key_string or not key_string.startswith("CR-"):
        return LicenseInfo(status=LicenseStatus.NONE)

    try:
        rest = key_string[3:]  # strip "CR-"
        if "." not in rest:
            raise ValueError("malformed key")

        payload_b64, sig_b64 = rest.rsplit(".", 1)

        # re-pad base64url
        def _pad(s):
            return s + "=" * (-len(s) % 4)

        payload_bytes = base64.urlsafe_b64decode(_pad(payload_b64))
        sig_bytes     = base64.urlsafe_b64decode(_pad(sig_b64))

        # verify signature — raises InvalidSignature if tampered
        pub = _get_public_key()
        pub.verify(sig_bytes, payload_bytes)

        data = json.loads(payload_bytes)
        expires = date.fromisoformat(data["expires"])
        issued  = date.fromisoformat(data["issued"])

        days_remaining = (expires - today).days

        if today > expires + timedelta(days=_GRACE_DAYS):
            status = LicenseStatus.EXPIRED
        elif today > expires:
            status = LicenseStatus.GRACE_PERIOD
        elif days_remaining <= _WARN_DAYS:
            status = LicenseStatus.EXPIRING_SOON
        else:
            status = LicenseStatus.VALID

        return LicenseInfo(
            status         = status,
            plan           = data.get("plan", "pro"),
            features       = set(data.get("features", [])),
            email          = data.get("email", ""),
            issued         = issued,
            expires        = expires,
            days_remaining = max(days_remaining, 0),
        )

    except InvalidSignature:
        return LicenseInfo(status=LicenseStatus.INVALID, error="Invalid signature — key may be tampered.")
    except Exception as e:
        return LicenseInfo(status=LicenseStatus.INVALID, error=f"Could not parse key: {e}")
