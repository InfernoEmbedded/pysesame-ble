"""Tests for device communication, segmentation, and commands in sesame-ble."""

import struct
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest

from pysesame_ble.const import (
    ITEM_CARD_NOTIFY,
    ITEM_DOOR_CLOSED,
    ITEM_DOOR_OPEN,
    ITEM_FINGER_NOTIFY,
    ITEM_LOCK,
    ITEM_MECH_SETTING,
    ITEM_MECH_STATUS,
    ITEM_PASSCODE_NOTIFY,
    ITEM_UNLOCK,
)
from pysesame_ble.device import (
    BaseKeypad,
    SesameBot,
    SesameDevice,
    SesameKeypad,
    SesameLock,
    SesameOpenSensor,
    SesameSegmentLayer,
    create_sesame_device,
)
from pysesame_ble.exceptions import (
    SesameAuthenticationError,
    SesameCommandError,
    SesameConnectionError,
)
from pysesame_ble.models import ProductModels, SesameAdData

TEST_UUID = UUID("01234567-89ab-cdef-0123-456789abcdef")


def test_segment_layer_segment_and_feed() -> None:
    """Test packet segmentation and reassembly through SesameSegmentLayer."""
    segmenter = SesameSegmentLayer()
    original_payload = b"Hello, Candy House Sesame BLE protocol segmentation testing!"

    # Unencrypted segmentation
    packets = segmenter.segment_payload(original_payload, encrypt=False)
    assert len(packets) > 1

    # First packet starts with 0x01 (start)
    assert packets[0][0] & 0x01
    # Last packet ends with 0x02 (end)
    assert packets[-1][0] & 0x02
    # Not encrypted
    assert not (packets[0][0] & 0x80)

    # Reassemble
    result = None
    for p in packets:
        result = segmenter.feed_packet(p)

    assert result is not None
    assembled_payload, _header, is_encrypted = result
    assert assembled_payload == original_payload
    assert is_encrypted is False


def test_segment_layer_encrypted_flag() -> None:
    """Test that encrypted packets carry bit 7 set."""
    segmenter = SesameSegmentLayer()
    payload = b"Encrypted data packet"
    packets = segmenter.segment_payload(payload, encrypt=True)
    assert packets[0][0] & 0x80

    result = None
    for p in packets:
        result = segmenter.feed_packet(p)

    assert result is not None
    _, _, is_encrypted = result
    assert is_encrypted is True


def test_create_sesame_device_factory() -> None:
    """Test factory creates SesameLock for lock models and SesameKeypad for touch/keypad."""
    lock_ad = SesameAdData(
        model_id=ProductModels.SESAME5.value, is_registered=True, device_uuid=TEST_UUID
    )
    keypad_ad = SesameAdData(
        model_id=ProductModels.SESAME_TOUCH_PRO.value, is_registered=True, device_uuid=TEST_UUID
    )
    bot_ad = SesameAdData(
        model_id=ProductModels.SESAME_BOT1.value, is_registered=True, device_uuid=TEST_UUID
    )
    sensor_ad = SesameAdData(
        model_id=ProductModels.SESAME_OPEN_SENSOR1.value, is_registered=True, device_uuid=TEST_UUID
    )
    bike_ad = SesameAdData(
        model_id=ProductModels.SESAME_BIKE2.value, is_registered=True, device_uuid=TEST_UUID
    )

    mock_ble = MagicMock()
    mock_ble.address = "AA:BB:CC:DD:EE:FF"

    assert isinstance(create_sesame_device(mock_ble, lock_ad, secret_key="00" * 16), SesameLock)
    assert isinstance(create_sesame_device(mock_ble, keypad_ad, secret_key="00" * 16), SesameKeypad)
    assert isinstance(create_sesame_device(mock_ble, bot_ad, secret_key="00" * 16), SesameBot)
    assert isinstance(
        create_sesame_device(mock_ble, sensor_ad, secret_key="00" * 16), SesameOpenSensor
    )
    assert isinstance(create_sesame_device(mock_ble, bike_ad, secret_key="00" * 16), SesameLock)


@pytest.mark.asyncio
async def test_device_not_connected_errors() -> None:
    """Test operations when device is not connected or logged in raise expected errors."""
    mock_ble = MagicMock()
    mock_ble.address = "AA:BB:CC:DD:EE:FF"
    ad = SesameAdData(model_id=5, is_registered=True, device_uuid=TEST_UUID)
    dev = SesameLock(mock_ble, ad, secret_key="00" * 16)

    assert dev.is_connected is False
    assert dev.is_logged_in is False

    with pytest.raises(SesameAuthenticationError, match="not logged in"):
        await dev.lock()

    with pytest.raises(SesameAuthenticationError, match="not logged in"):
        await dev.unlock()


@pytest.mark.asyncio
async def test_sesame_lock_mech_status_published() -> None:
    """Test SesameLock on_published updates state and invokes status callback."""
    mock_ble = MagicMock()
    mock_ble.address = "AA:BB:CC:DD:EE:FF"
    ad = SesameAdData(model_id=5, is_registered=True, device_uuid=TEST_UUID)

    status_called = False

    def on_status(device, status):
        nonlocal status_called
        status_called = True

    lock = SesameLock(mock_ble, ad, secret_key="00" * 16, status_callback=on_status)

    # Payload: raw_battery (uint16_t), target (int16_t), position (int16_t), flags (uint8_t)
    # 2900 mV * 2 = 5800 mV (5.80V), target = 0, current = 90, flags = 0x02 (locked)
    raw_status = struct.pack("<HhhB", 2900, 0, 90, 0x02)
    lock.on_published(ITEM_MECH_STATUS, raw_status)

    assert lock.battery_voltage == 5.8
    assert lock.current_angle == 90
    assert lock.target_angle == 0
    assert lock.is_locked is True
    assert lock.is_unlocked is False
    assert status_called is True

    # Test MECH_SETTING publish
    # lock_pos = 0, unlock_pos = 90, autolock = 10s
    setting_payload = struct.pack("<hhH", 0, 90, 10)
    lock.on_published(ITEM_MECH_SETTING, setting_payload)
    assert lock.lock_position == 0
    assert lock.unlock_position == 90
    assert lock.auto_lock_second == 10


@pytest.mark.asyncio
async def test_sesame_lock_send_command_locked() -> None:
    """Test SesameLock sending lock/unlock calls send_command."""
    mock_ble = MagicMock()
    mock_ble.address = "AA:BB:CC:DD:EE:FF"
    ad = SesameAdData(model_id=5, is_registered=True, device_uuid=TEST_UUID)
    lock = SesameLock(mock_ble, ad, secret_key="00" * 16)
    lock.is_logged_in = True
    lock.send_command = AsyncMock()

    await lock.lock(history_name="Test User")
    lock.send_command.assert_awaited_once()
    args, kwargs = lock.send_command.call_args
    assert args[0] == ITEM_LOCK
    assert b"Test User" in args[1]
    assert kwargs.get("encrypt") is True

    lock.send_command.reset_mock()
    await lock.unlock(history_name="Test User")
    lock.send_command.assert_awaited_once()
    args, kwargs = lock.send_command.call_args
    assert args[0] == ITEM_UNLOCK
    assert b"Test User" in args[1]


@pytest.mark.asyncio
async def test_keypad_credential_parsing() -> None:
    """Test SesameKeypad notifications for passcodes, cards, and fingerprints."""
    mock_ble = MagicMock()
    mock_ble.address = "AA:BB:CC:DD:EE:FF"
    ad = SesameAdData(
        model_id=ProductModels.SESAME_TOUCH.value, is_registered=True, device_uuid=TEST_UUID
    )

    keypad = SesameKeypad(mock_ble, ad, secret_key="00" * 16)

    # Passcode notify payload: type (1B), id_len (1B), id_bytes, name_len (1B), name_bytes
    # Type 0, 4 digits: 1, 2, 3, 4, Name: "Admin"
    code_bytes = bytes([1, 2, 3, 4])
    name_bytes = b"Admin"
    passcode_payload = (
        bytes([0, len(code_bytes)]) + code_bytes + bytes([len(name_bytes)]) + name_bytes
    )

    keypad.on_published(ITEM_PASSCODE_NOTIFY, passcode_payload)
    assert keypad.scanned_passcode is not None
    assert keypad.scanned_passcode["code"] == "1234"

    # Card notify payload: Type 0x80, ID: A1B2C3D4, Name: "Office Card"
    card_id = bytes([0xA1, 0xB2, 0xC3, 0xD4])
    card_name = b"Office Card"
    card_payload = bytes([0x80, len(card_id)]) + card_id + bytes([len(card_name)]) + card_name

    keypad.on_published(ITEM_CARD_NOTIFY, card_payload)
    assert keypad.scanned_card is not None
    assert keypad.scanned_card["uid"] == card_id.hex()

    # Fingerprint notify payload
    fp_id = bytes([1, 0])
    fp_name = b"Right Thumb"
    fp_payload = bytes([0, len(fp_id)]) + fp_id + bytes([len(fp_name)]) + fp_name

    keypad.on_published(ITEM_FINGER_NOTIFY, fp_payload)
    assert keypad.scanned_fingerprint is not None
    assert keypad.scanned_fingerprint["uid"] == fp_id.hex()


@pytest.mark.asyncio
async def test_open_sensor_published() -> None:
    """Test SesameOpenSensor door status transitions."""
    mock_ble = MagicMock()
    mock_ble.address = "AA:BB:CC:DD:EE:FF"
    ad = SesameAdData(
        model_id=ProductModels.SESAME_OPEN_SENSOR1.value, is_registered=True, device_uuid=TEST_UUID
    )
    sensor = SesameOpenSensor(mock_ble, ad)

    sensor.on_published(ITEM_DOOR_OPEN, b"")
    assert sensor.door_status == "open"

    sensor.on_published(ITEM_DOOR_CLOSED, b"")
    assert sensor.door_status == "closed"


@pytest.mark.asyncio
async def test_sesame_bot_commands() -> None:
    """Test SesameBot click, lock, and unlock methods."""
    mock_ble = MagicMock()
    mock_ble.address = "AA:BB:CC:DD:EE:FF"
    ad = SesameAdData(
        model_id=ProductModels.SESAME_BOT1.value, is_registered=True, device_uuid=TEST_UUID
    )
    bot = SesameBot(mock_ble, ad, secret_key="00" * 16)
    bot.is_logged_in = True
    bot.send_command = AsyncMock()

    await bot.click()
    bot.send_command.assert_awaited_once_with(ITEM_LOCK, b"", encrypt=True)

    bot.send_command.reset_mock()
    await bot.lock()
    bot.send_command.assert_awaited_once_with(ITEM_LOCK, b"", encrypt=True)

    bot.send_command.reset_mock()
    await bot.unlock()
    bot.send_command.assert_awaited_once_with(ITEM_UNLOCK, b"", encrypt=True)


@pytest.mark.asyncio
async def test_device_pause_auto_reconnect() -> None:
    """Test pausing and resuming auto-reconnection and pause on disconnect."""
    mock_ble = MagicMock()
    mock_ble.address = "AA:BB:CC:DD:EE:FF"
    dev = SesameDevice(mock_ble)

    dev.pause_auto_reconnect()
    assert dev._auto_reconnect_paused is True

    dev.resume_auto_reconnect()
    assert dev._auto_reconnect_paused is False

    await dev.disconnect()
    assert dev._auto_reconnect_paused is True


def test_device_set_ble_device_and_fw_alias() -> None:
    """Test updating the BLEDevice reference and fw_version alias."""
    mock_ble_1 = MagicMock()
    mock_ble_1.address = "AA:BB:CC:DD:EE:11"
    dev = SesameDevice(mock_ble_1)
    assert dev.address == "AA:BB:CC:DD:EE:11"
    assert dev.fw_version is None

    mock_ble_2 = MagicMock()
    mock_ble_2.address = "AA:BB:CC:DD:EE:22"
    dev.set_ble_device(mock_ble_2)
    assert dev.address == "AA:BB:CC:DD:EE:22"

    dev._firmware_version = "3.5.1"
    assert dev.fw_version == "3.5.1"
    assert dev.firmware_version == "3.5.1"


@pytest.mark.asyncio
async def test_connect_missing_ble_device_error() -> None:
    """Test that connecting without a BLE device raises SesameConnectionError."""
    dev = SesameDevice(None)
    with pytest.raises(SesameConnectionError, match="No BLEDevice configured"):
        await dev.connect()


def test_on_gatt_notification_error_code() -> None:
    """Test that GATT notification with non-zero result code sets error_code."""
    mock_ble = MagicMock()
    mock_ble.address = "AA:BB:CC:DD:EE:FF"
    dev = SesameDevice(mock_ble)

    fut = MagicMock()
    fut.done.return_value = False
    dev._pending_responses[82] = fut

    # Response payload: OP_RESPONSE (7), item_code (82), result_code (5)
    raw_packet = bytes([0x03, 0x07, 82, 5])
    dev._on_gatt_notification(MagicMock(), bytearray(raw_packet))

    fut.set_exception.assert_called_once()
    exc = fut.set_exception.call_args[0][0]
    assert isinstance(exc, SesameCommandError)
    assert exc.error_code == 5


@pytest.mark.asyncio
async def test_base_keypad_inheritance_and_scheduling() -> None:
    """Test BaseKeypad inheritance and passcode schedule virtualization."""
    assert issubclass(SesameKeypad, BaseKeypad)

    mock_ble = MagicMock()
    mock_ble.address = "AA:BB:CC:DD:EE:FF"
    keypad = SesameKeypad(mock_ble)
    assert isinstance(keypad, BaseKeypad)

    keypad.add_passcode = AsyncMock()
    keypad.delete_passcode = AsyncMock()

    # Passcode that should be active
    schedules = {
        "user1": {
            "name": "Active User",
            "code": "123456",
            "start": "2000-01-01T00:00:00",
            "end": "2099-01-01T00:00:00",
        }
    }
    changed = await keypad.apply_passcode_schedules(schedules)
    assert changed is True
    keypad.add_passcode.assert_awaited_once_with("123456", "Active User")
