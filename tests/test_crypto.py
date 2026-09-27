"""Tests for the cryptographic primitives of sesame-ble."""

import pytest

from sesame_ble.crypto import (
    SesameCipher,
    derive_device_secret,
    derive_session_token_key,
    generate_ecc_keypair,
)
from sesame_ble.exceptions import SesameAuthenticationError


def test_ecc_keypair_generation() -> None:
    """Test generating a NIST P-256 ECC key pair."""
    pub_bytes, priv_key = generate_ecc_keypair()
    assert len(pub_bytes) == 64
    assert priv_key is not None


def test_ecdh_device_secret_derivation() -> None:
    """Test ECDH shared secret derivation between device and app."""
    # Simulate device keypair
    dev_pub, dev_priv = generate_ecc_keypair()
    # Simulate app keypair
    app_pub, app_priv = generate_ecc_keypair()

    # App derives secret using device's public key
    app_secret = derive_device_secret(dev_pub, app_priv)
    # Device derives secret using app's public key
    dev_secret = derive_device_secret(app_pub, dev_priv)

    assert len(app_secret) == 16
    assert app_secret == dev_secret


def test_derive_session_token_key() -> None:
    """Test AES-CMAC session key derivation."""
    secret = b"0123456789abcdef"
    token = b"\xaa\xbb\xcc\xdd"

    session_key = derive_session_token_key(secret, token)
    assert len(session_key) == 16

    # Repeated calls must produce identical session keys
    assert derive_session_token_key(secret, token) == session_key


def test_sesame_cipher_encrypt_decrypt() -> None:
    """Test AES-CCM encryption and decryption roundtrip."""
    session_token = b"\x12\x34\x56\x78"
    session_key = b"abcdef0123456789"

    sender = SesameCipher(session_token, session_key)
    receiver = SesameCipher(session_token, session_key)

    plaintext = b"Test Sesame Payload"
    ciphertext = sender.encrypt_payload(plaintext)

    # 4-byte MAC appended to ciphertext
    assert len(ciphertext) == len(plaintext) + 4
    assert ciphertext != plaintext

    decrypted = receiver.decrypt_payload(ciphertext)
    assert decrypted == plaintext


def test_sesame_cipher_sequence_mismatch_fails() -> None:
    """Test that out-of-order packets fail authentication."""
    session_token = b"\x12\x34\x56\x78"
    session_key = b"abcdef0123456789"

    sender = SesameCipher(session_token, session_key)
    receiver = SesameCipher(session_token, session_key)

    # Send first packet
    sender.encrypt_payload(b"Msg 1")
    # Send second packet
    msg2_cipher = sender.encrypt_payload(b"Msg 2")

    # Receiver expects seq=0, but receives msg2 (seq=1) -> decryption should fail
    with pytest.raises(SesameAuthenticationError):
        receiver.decrypt_payload(msg2_cipher)


def test_sesame_cipher_tampered_ciphertext() -> None:
    """Test that modified ciphertext raises SesameAuthenticationError."""
    session_token = b"\x12\x34\x56\x78"
    session_key = b"abcdef0123456789"

    sender = SesameCipher(session_token, session_key)
    receiver = SesameCipher(session_token, session_key)

    ciphertext = bytearray(sender.encrypt_payload(b"Secret command"))
    ciphertext[0] ^= 0xFF  # tamper with first byte

    with pytest.raises(SesameAuthenticationError):
        receiver.decrypt_payload(bytes(ciphertext))
