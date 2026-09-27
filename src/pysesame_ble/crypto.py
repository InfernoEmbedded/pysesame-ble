"""Cryptographic functions for the Sesame OS3 BLE protocol.

Implements ECDH P-256 key agreement, AES-CMAC session key derivation,
and AES-CCM message encryption/decryption as defined in the official docs:
https://github.com/CANDY-HOUSE/API_document/blob/main/SesameOS3/bluetooth.md
"""

import logging

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .exceptions import SesameAuthenticationError

logger = logging.getLogger(__name__)


class SesameCipher:
    """Manages secure communication using AES-CCM for a Sesame BLE session."""

    def __init__(self, session_token: bytes, session_key: bytes) -> None:
        """Initialize the cipher with the session token and derived key.

        Args:
            session_token: 4-byte session token (random code).
            session_key: 16-byte session key (Token derived via AES-CMAC).
        """
        self._token = session_token
        self._key = session_key
        self._encrypt_seq = 0
        self._decrypt_seq = 0
        self._aesccm = AESCCM(session_key, tag_length=4)

    def _build_nonce(self, counter: int) -> bytes:
        """Constructs the 13-byte CCM_IV: 8-byte count (LE) + 1-byte nouse (0) + 4-byte token."""
        return counter.to_bytes(8, byteorder="little") + b"\x00" + self._token

    def encrypt_payload(self, plaintext: bytes) -> bytes:
        """Encrypts data using AES-CCM (13-byte IV, 1-byte AAD: 0x00, 4-byte MAC/tag)."""
        nonce = self._build_nonce(self._encrypt_seq)
        self._encrypt_seq += 1
        return self._aesccm.encrypt(nonce, plaintext, b"\x00")

    def decrypt_payload(self, ciphertext: bytes) -> bytes:
        """Decrypts and verifies data using AES-CCM."""
        nonce = self._build_nonce(self._decrypt_seq)
        self._decrypt_seq += 1

        try:
            return self._aesccm.decrypt(nonce, ciphertext, b"\x00")
        except Exception as err:
            logger.error(
                "Decryption failed!\n  Nonce: %s\n  Ciphertext: %s",
                nonce.hex(),
                ciphertext.hex(),
            )
            raise SesameAuthenticationError(f"Failed to decrypt Sesame packet: {err}") from err


def generate_ecc_keypair() -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    """Generates a NIST P-256 ECC key pair for Sesame registration.

    Returns:
        A tuple of (public_key_raw_64_bytes, private_key_object).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_bytes = private_key.public_key().public_bytes(
        encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
    )
    # Remove the 0x04 uncompressed prefix byte
    return public_bytes[1:], private_key


def derive_device_secret(
    device_pubkey_raw: bytes, app_privkey: ec.EllipticCurvePrivateKey
) -> bytes:
    """Derives the 16-byte device secret using ECDH.

    Args:
        device_pubkey_raw: Device's 64-byte uncompressed public key (no 0x04 prefix).
        app_privkey: The app's private ECC key.
    """
    uncompressed_pub = b"\x04" + device_pubkey_raw
    device_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), uncompressed_pub
    )
    shared_secret = app_privkey.exchange(ec.ECDH(), device_public_key)
    return shared_secret[:16]


def derive_session_token_key(device_secret: bytes, session_token: bytes) -> bytes:
    """Derives the 16-byte session key (Token) by signing the random code using AES-CMAC.

    Formula: AES_CMAC(key: device_secret, input: session_token)
    """
    c = cmac.CMAC(algorithms.AES(device_secret))
    c.update(session_token)
    return c.finalize()
