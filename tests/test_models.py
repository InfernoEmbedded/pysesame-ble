"""Tests for data models and helpers in sesame-ble."""

import struct
from uuid import UUID

import pytest

from sesame_ble.const import COMPANY_ID
from sesame_ble.models import (
    ProductModels,
    SesameAdData,
    calculate_battery_percentage,
    get_sesame_mfg_data,
    is_bike_lock_model,
    is_bot_model,
    is_keypad_model,
    is_lock_model,
    is_open_sensor_model,
)

TEST_UUID = UUID("01234567-89ab-cdef-0123-456789abcdef")


def test_model_detection_helpers() -> None:
    """Test model classification helpers."""
    assert is_lock_model(ProductModels.SESAME5) is True
    assert is_lock_model(ProductModels.SESAME5_PRO) is True
    assert is_lock_model(ProductModels.SESAME6) is True
    assert is_lock_model(ProductModels.SESAME_TOUCH) is False

    assert is_keypad_model(ProductModels.SESAME_TOUCH) is True
    assert is_keypad_model(ProductModels.SESAME_TOUCH_PRO) is True
    assert is_keypad_model(ProductModels.SESAME_FACE) is True
    assert is_keypad_model(ProductModels.SESAME5) is False

    assert is_bot_model(ProductModels.SESAME_BOT1) is True
    assert is_bot_model(ProductModels.SESAME_BOT2) is True
    assert is_bot_model(ProductModels.SESAME5) is False

    assert is_open_sensor_model(ProductModels.SESAME_OPEN_SENSOR1) is True
    assert is_open_sensor_model(ProductModels.SESAME_OPEN_SENSOR2) is True
    assert is_open_sensor_model(ProductModels.SESAME5) is False

    assert is_bike_lock_model(ProductModels.SESAME_BIKE2) is True
    assert is_bike_lock_model(ProductModels.SESAME_BIKE3) is True
    assert is_bike_lock_model(ProductModels.SESAME5) is False


def test_calculate_battery_percentage() -> None:
    """Test linear battery percentage interpolation."""
    assert calculate_battery_percentage(6.0) == 100
    assert calculate_battery_percentage(5.85) == 100
    assert calculate_battery_percentage(5.60) == 50
    assert calculate_battery_percentage(5.45) == 26
    assert calculate_battery_percentage(4.6) == 0
    assert calculate_battery_percentage(4.0) == 0


def test_sesame_mfg_data_extraction() -> None:
    """Test extracting manufacturer data from advertising packets."""
    payload = b"\x05\x00\x01" + TEST_UUID.bytes
    mfg_dict = {COMPANY_ID: payload}

    cid, data = get_sesame_mfg_data(mfg_dict)
    assert cid == COMPANY_ID
    assert data == payload

    # Test unknown company ID with valid length fallback
    fallback_dict = {0x9999: payload}
    cid, data = get_sesame_mfg_data(fallback_dict)
    assert cid == 0x9999
    assert data == payload

    # Test empty dict
    assert get_sesame_mfg_data({}) is None


def test_sesame_ad_data_decode() -> None:
    """Test decoding advertisement data."""
    raw = struct.pack("<HB16s", 5, 1, TEST_UUID.bytes)
    ad = SesameAdData.decode(raw)
    assert ad.model_id == 5
    assert ad.is_registered is True
    assert ad.device_uuid == TEST_UUID

    unreg_raw = struct.pack("<HB16s", 21, 0, TEST_UUID.bytes)
    unreg_ad = SesameAdData.decode(unreg_raw)
    assert unreg_ad.model_id == 21
    assert unreg_ad.is_registered is False

    # Short payload raises ValueError
    with pytest.raises(ValueError, match="too short"):
        SesameAdData.decode(b"\x00\x01")
