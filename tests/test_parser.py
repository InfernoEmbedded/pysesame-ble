"""Tests for QR Code parser and generator in sesame-ble."""

from uuid import UUID

import pytest

from sesame_ble.exceptions import SesameKeyError
from sesame_ble.parser import SesameQRCode

TEST_UUID = UUID("01234567-89ab-cdef-0123-456789abcdef")


def test_qr_code_from_url_and_to_url() -> None:
    """Test round-trip parsing and generation of Candy House ssm:// URLs."""
    secret_key = bytes(range(16))
    qr = SesameQRCode(
        device_name="Front Door",
        key_level=0,
        model_id=5,  # SESAME5
        device_uuid=TEST_UUID,
        secret_key=secret_key,
    )

    url = qr.to_url()
    assert url.startswith("ssm://UI?t=sk")
    assert "n=Front+Door" in url or "n=Front%20Door" in url

    # Parse back
    parsed = SesameQRCode.from_url(url)
    assert parsed.device_name == "Front Door"
    assert parsed.key_level == 0
    assert parsed.model_id == 5
    assert parsed.device_uuid == TEST_UUID
    assert parsed.secret_key == secret_key


def test_qr_code_missing_sk() -> None:
    """Test that missing sk query parameter raises SesameKeyError."""
    with pytest.raises(SesameKeyError, match="missing secret key"):
        SesameQRCode.from_url("ssm://UI?t=sk&n=Test")


def test_qr_code_invalid_base64() -> None:
    """Test that malformed base64 raises SesameKeyError."""
    with pytest.raises(SesameKeyError, match="Failed to decode base64"):
        SesameQRCode.from_url("ssm://UI?t=sk&sk=!!!invalid_base64!!!")


def test_qr_code_short_payload() -> None:
    """Test that base64 payload shorter than 39 bytes raises SesameKeyError."""
    short_b64 = "AQIDBA=="  # 4 bytes decoded
    with pytest.raises(SesameKeyError, match="too short"):
        SesameQRCode.from_url(f"ssm://UI?t=sk&sk={short_b64}")
