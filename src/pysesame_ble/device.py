"""BLE transport, protocol state machine, and device classes for Candy House Sesame.

Based strictly on the official documentation:
https://github.com/CANDY-HOUSE/API_document
"""

import asyncio
import base64
import contextlib
import datetime
import logging
import random
import struct
import time
from collections.abc import Callable
from typing import Any
from uuid import UUID

import bleak_retry_connector
from bleak import BleakClient, BleakScanner, BLEDevice
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.exc import BleakDeviceNotFoundError

from .const import (
    ITEM_ADD_SESAME,
    ITEM_AUTOLOCK,
    ITEM_CARD_ADD,
    ITEM_CARD_CHANGE,
    ITEM_CARD_DELETE,
    ITEM_CARD_FIRST,
    ITEM_CARD_GET,
    ITEM_CARD_LAST,
    ITEM_CARD_MODE_SET,
    ITEM_CARD_NOTIFY,
    ITEM_CARD_VERIFY_TO_CLOUD,
    ITEM_DOOR_CLOSED,
    ITEM_DOOR_OPEN,
    ITEM_ENABLE_DFU,
    ITEM_FACE_CHANGE,
    ITEM_FACE_DELETE,
    ITEM_FACE_FIRST,
    ITEM_FACE_GET,
    ITEM_FACE_LAST,
    ITEM_FACE_MODE_SET,
    ITEM_FACE_NOTIFY,
    ITEM_FINGER_CHANGE,
    ITEM_FINGER_DELETE,
    ITEM_FINGER_FIRST,
    ITEM_FINGER_GET,
    ITEM_FINGER_LAST,
    ITEM_FINGER_MODE_SET,
    ITEM_FINGER_NOTIFY,
    ITEM_HISTORY,
    ITEM_HISTORY_DELETE,
    ITEM_INITIAL,
    ITEM_KEYPAD_LOCK_LIST,
    ITEM_LOCK,
    ITEM_LOGIN,
    ITEM_MAGNET,
    ITEM_MECH_SETTING,
    ITEM_MECH_STATUS,
    ITEM_OPS_TIMER_SETTING,
    ITEM_PALM_CHANGE,
    ITEM_PALM_DELETE,
    ITEM_PALM_FIRST,
    ITEM_PALM_GET,
    ITEM_PALM_LAST,
    ITEM_PALM_MODE_SET,
    ITEM_PALM_NOTIFY,
    ITEM_PASSCODE_ADD,
    ITEM_PASSCODE_CHANGE,
    ITEM_PASSCODE_DELETE,
    ITEM_PASSCODE_FIRST,
    ITEM_PASSCODE_GET,
    ITEM_PASSCODE_LAST,
    ITEM_PASSCODE_MODE_SET,
    ITEM_PASSCODE_NOTIFY,
    ITEM_PASSCODE_VERIFY_TO_CLOUD,
    ITEM_REGISTRATION,
    ITEM_REMOVE_SESAME,
    ITEM_TIME,
    ITEM_UNLOCK,
    ITEM_VERSION_TAG,
    MTU_SIZE,
    OP_PUBLISH,
    OP_RESPONSE,
    RX_CHAR_UUID,
    TX_CHAR_UUID,
)
from .crypto import (
    SesameCipher,
    derive_device_secret,
    derive_session_token_key,
    generate_ecc_keypair,
)
from .exceptions import (
    SesameAuthenticationError,
    SesameCommandError,
    SesameConnectionError,
    SesameRegistrationError,
)
from .models import (
    SesameAdData,
    calculate_battery_percentage,
    get_sesame_mfg_data,
    is_bike_lock_model,
    is_bot_model,
    is_face_keypad_model,
    is_keypad_model,
    is_open_sensor_model,
)

logger = logging.getLogger(__name__)


class SesameSegmentLayer:
    """Handles GATT packet fragmentation and reassembly."""

    def __init__(self) -> None:
        self._rx_buffer = bytearray()

    def feed_packet(self, data: bytes) -> tuple[bytes, bool, bool] | None:
        """Processes an incoming raw BLE GATT packet.

        Header bit layout:
        Bit 0 (0x01): Start of message (BEGINNING)
        Bit 1 (0x02): End of plaintext message (PLAINTEXT_END)
        Bit 2 (0x04): End of encrypted message (ENCRYPTED_END)

        Returns:
            A tuple of (message_payload, is_complete, is_encrypted) or None if incomplete.
        """
        if not data:
            return None

        header = data[0]
        body = data[1:]

        is_start = bool(header & 0x01)
        is_plain_end = bool(header & 0x02)
        is_crypt_end = bool(header & 0x04)
        is_end = is_plain_end or is_crypt_end

        if is_start:
            self._rx_buffer.clear()

        self._rx_buffer.extend(body)

        if is_end:
            full_payload = bytes(self._rx_buffer)
            self._rx_buffer.clear()
            return full_payload, True, is_crypt_end

        return None

    def segment_payload(self, data: bytes, encrypt: bool) -> list[bytes]:
        """Fragments an outgoing payload into MTU-sized GATT packets."""
        packets = []
        total_len = len(data)
        chunk_size = MTU_SIZE - 1  # 1-byte segment header
        offset = 0

        while offset < total_len:
            is_start = offset == 0
            is_end = (offset + chunk_size) >= total_len
            chunk = data[offset : offset + chunk_size]

            header = 0
            if is_start:
                header |= 0x01
            if is_end:
                header |= 0x04 if encrypt else 0x02

            packets.append(bytes([header]) + chunk)
            offset += chunk_size

        return packets


class SesameDevice:
    """Coordinates the BLE connection, session login, and command loop."""

    def __init__(
        self,
        ble_device: BLEDevice | None,
        ad_data: SesameAdData | None = None,
        secret_key: str | bytes | None = None,
        status_callback: Callable[[object, object], None] | None = None,
        reconnect_attempts: int = 0,
    ) -> None:
        self._ble_device = ble_device
        self.ad_data = ad_data
        self.product_model = ad_data.model_id if ad_data else None

        if isinstance(secret_key, bytes):
            self._secret: bytes | None = secret_key
        elif isinstance(secret_key, str) and secret_key:
            self._secret = bytes.fromhex(secret_key)
        else:
            self._secret = None

        self._reconnect_limit = reconnect_attempts
        self._status_cb = status_callback

        self._segmenter = SesameSegmentLayer()
        self._client: BleakClient | None = None
        self._cipher: SesameCipher | None = None
        self._reconnect_task: asyncio.Task[None] | None = None
        self._auto_reconnect_paused = False

        self._login_event = asyncio.Event()
        self._send_lock = asyncio.Lock()

        self._session_token: bytes | None = None
        self._token_future: asyncio.Future[bytes] | None = None
        self._pending_responses: dict[int, asyncio.Future[bytes]] = {}
        self.is_logged_in = False
        self.mech_status: Any = None
        self._background_tasks: set[asyncio.Task[Any]] = set()

    def set_ble_device(self, ble_device: BLEDevice) -> None:
        """Update the underlying BLEDevice reference."""
        self._ble_device = ble_device

    @property
    def address(self) -> str:
        """The BLE MAC address."""
        if self._ble_device and getattr(self._ble_device, "address", None):
            return self._ble_device.address
        return getattr(self, "_address", None) or "00:00:00:00:00:00"

    @property
    def mac_address(self) -> str:
        """The BLE MAC address for compatibility."""
        return self.address

    @property
    def fw_version(self) -> str | None:
        """Return the current firmware version string if fetched (compatibility alias)."""
        return self.firmware_version

    @property
    def is_connected(self) -> bool:
        """Return True if BLE client is actively connected."""
        return self._client is not None and self._client.is_connected

    async def connect(self) -> None:
        """Connects and starts notifications, waiting for the initial session token."""
        if self._ble_device is None:
            raise SesameConnectionError("No BLEDevice configured")

        if self._reconnect_task and not self._reconnect_task.done():
            if asyncio.current_task() is not self._reconnect_task:
                raise SesameConnectionError("Cannot connect while auto-reconnecting")

        if self.is_connected:
            raise SesameConnectionError("Already connected")

        logger.info("Connecting to Sesame [address=%s]", self.address)

        try:
            self._client = await bleak_retry_connector.establish_connection(
                BleakClient,
                self._ble_device,
                "sesame_ble",
                disconnected_callback=self._on_disconnect,
            )
        except Exception:
            try:
                self._client = BleakClient(
                    self._ble_device, disconnected_callback=self._on_disconnect
                )
                await self._client.connect()
            except BleakDeviceNotFoundError as err:
                raise SesameConnectionError("BLE device not found") from err
            except Exception as err:
                raise SesameConnectionError(f"Connection failed: {err}") from err

        try:
            self._token_future = asyncio.get_running_loop().create_future()
            await self._client.start_notify(RX_CHAR_UUID, self._on_gatt_notification)
            logger.debug("Waiting for session token publish")
            await asyncio.wait_for(self._token_future, timeout=15.0)
        except Exception:
            await self.disconnect()
            raise
        finally:
            self._token_future = None

    async def register(self) -> str:
        """Performs cryptographic registration handshake and returns derived secret key hex."""
        if not self._session_token:
            raise SesameRegistrationError("Session token not received yet")

        app_pub, app_priv = generate_ecc_keypair()
        timestamp = int(time.time()).to_bytes(4, "little")

        try:
            response = await self.send_command(
                ITEM_REGISTRATION, app_pub + timestamp, encrypt=False
            )
            device_pub = response[-64:]
            secret_key = derive_device_secret(device_pub, app_priv)
            return secret_key.hex()
        except Exception as err:
            self._reset_state()
            raise SesameRegistrationError(f"Registration failed: {err}") from err

    async def login(self) -> int:
        """Performs cryptographic login handshake."""
        if self.is_logged_in:
            raise SesameAuthenticationError("Already logged in")
        if not self._secret:
            raise SesameAuthenticationError("Secret key is missing")
        if not self._session_token:
            raise SesameAuthenticationError("Session token not received yet")

        token = self._session_token
        session_key = derive_session_token_key(self._secret, token)
        self._cipher = SesameCipher(token, session_key)

        try:
            # Login payload is first 4 bytes of session key
            response = await self.send_command(ITEM_LOGIN, session_key[:4], encrypt=False)
            device_time = int.from_bytes(response, "little")
            self.is_logged_in = True
            logger.info("Logged in successfully. Device time: %d", device_time)

            # Auto-sync time if drift is detected (more than 5 seconds difference)
            host_time = int(time.time())
            if abs(device_time - host_time) > 5:
                try:
                    await self.sync_time()
                except Exception as e:
                    logger.warning("Failed to automatically synchronize clock on login: %s", e)

            # Wait for mechanical settings/status on devices that support it
            if isinstance(self, SesameLock) or is_keypad_model(self.product_model):
                try:
                    await asyncio.wait_for(self._login_event.wait(), timeout=5.0)
                except TimeoutError:
                    logger.warning(
                        "Timed out waiting for initial mechanical settings/status publish"
                    )
            else:
                self._login_event.set()

            if self._status_cb:
                self._status_cb(self, self)

            # Request firmware version in background on successful login
            fw_task = asyncio.create_task(self.request_firmware_version())
            self._background_tasks.add(fw_task)
            fw_task.add_done_callback(self._background_tasks.discard)

            return device_time
        except Exception as err:
            await self.disconnect()
            raise SesameAuthenticationError(f"Login failed: {err}") from err

    @property
    def firmware_version(self) -> str | None:
        """Return the current firmware version string if fetched."""
        return getattr(self, "_firmware_version", None)

    async def request_firmware_version(self) -> str | None:
        """Request the firmware version tag from the device over BLE."""
        if not self.is_logged_in:
            return self.firmware_version
        try:
            res = await self.send_command(ITEM_VERSION_TAG, b"")
            if res:
                ver_str = res.decode("utf-8", errors="ignore").strip("\x00").strip()
                if ver_str:
                    self._firmware_version = ver_str
                    logger.info("Retrieved firmware version for %s: %s", self.address, ver_str)
                    if self._status_cb:
                        self._status_cb(self, self)
                    return ver_str
        except Exception as err:
            logger.debug("Failed to fetch firmware version from %s: %s", self.address, err)
        return self.firmware_version

    async def enable_dfu(self) -> None:
        """Put device into BLE DFU mode for over-the-air firmware updates."""
        if not self.is_logged_in:
            raise SesameCommandError("Device is not logged in")
        logger.info("Sending ENABLE_DFU command to device %s", self.address)
        await self.send_command(ITEM_ENABLE_DFU, b"\x01", wait_for_response=False)

    async def sync_time(self) -> None:
        """Synchronizes the device's clock with the host time."""
        if not self.is_logged_in:
            raise SesameCommandError("Device is not logged in")
        timestamp = int(time.time())
        logger.info(
            "Synchronizing time on device [address=%s, timestamp=%d]",
            self.address,
            timestamp,
        )
        payload = struct.pack("<I", timestamp)
        await self.send_command(ITEM_TIME, payload, encrypt=True)

    async def disconnect(self) -> None:
        """Gracefully disconnects and resets state."""
        self.pause_auto_reconnect()
        self._reset_state()
        if self._client:
            try:
                await self._client.disconnect()
            except Exception:
                pass
            finally:
                self._client = None

    def _reset_state(self) -> None:
        was_logged_in = self.is_logged_in
        self.is_logged_in = False
        self._cipher = None
        self._session_token = None
        if self._token_future and not self._token_future.done():
            self._token_future.set_exception(
                SesameConnectionError("Disconnected before handshake completed")
            )
        self._token_future = None
        self.mech_status = None
        self._login_event.clear()

        for fut in list(self._pending_responses.values()):
            if not fut.done():
                fut.cancel()
        self._pending_responses.clear()
        self._segmenter = SesameSegmentLayer()

        if was_logged_in and self._status_cb:
            self._status_cb(self, self)

    def pause_auto_reconnect(self) -> None:
        """Cancels and suppresses automatic reconnection during DFU or manual disconnect."""
        self._auto_reconnect_paused = True
        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            self._reconnect_task = None

    def resume_auto_reconnect(self) -> None:
        """Restores automatic reconnection."""
        self._auto_reconnect_paused = False

    def _on_disconnect(self, client: BleakClient) -> None:
        del client
        logger.warning("Sesame BLE disconnected unexpectedly [address=%s]", self.address)
        self._reset_state()
        if (
            not self._auto_reconnect_paused
            and self._reconnect_limit
            and (not self._reconnect_task or self._reconnect_task.done())
        ):
            self._reconnect_task = asyncio.create_task(self._auto_reconnect())

    async def _auto_reconnect(self) -> None:
        for attempt in range(self._reconnect_limit):
            delay = min(2**attempt + random.random(), 30.0)
            logger.info(
                "Scheduling reconnection attempt %d/%d in %.1fs",
                attempt + 1,
                self._reconnect_limit,
                delay,
            )
            await asyncio.sleep(delay)
            try:
                await self.connect()
                await self.login()
                logger.info("Auto-reconnection successful [address=%s]", self.address)
                return
            except Exception as e:
                logger.warning("Reconnection attempt %d failed: %s", attempt + 1, e)
                await self.disconnect()
        logger.error("Auto-reconnection limit reached. Connection abandoned.")

    def _on_gatt_notification(
        self, characteristic: BleakGATTCharacteristic, data: bytearray
    ) -> None:
        del characteristic
        res = self._segmenter.feed_packet(bytes(data))
        if not res:
            return

        payload, _, is_encrypted = res
        if is_encrypted:
            if not self._cipher:
                logger.warning("Received encrypted message before login cipher was configured")
                return
            payload = self._cipher.decrypt_payload(payload)

        if not payload:
            return

        op_code = payload[0]
        body = payload[1:]

        if op_code == OP_RESPONSE:
            if len(body) >= 2:
                item_code = body[0]
                result_code = body[1]
                response_payload = body[2:]

                fut = self._pending_responses.pop(item_code, None)
                if fut and not fut.done():
                    if result_code == 0:
                        fut.set_result(response_payload)
                    else:
                        fut.set_exception(
                            SesameCommandError(
                                f"Command error code: {result_code}", error_code=result_code
                            )
                        )
        elif op_code == OP_PUBLISH:
            if len(body) >= 1:
                item_code = body[0]
                publish_payload = body[1:]

                if item_code == ITEM_INITIAL:
                    self._session_token = publish_payload
                    if self._token_future and not self._token_future.done():
                        self._token_future.set_result(publish_payload)
                else:
                    self.on_published(item_code, publish_payload)

    def on_published(self, item_code: int, payload: bytes) -> None:
        """To be overridden by subclasses."""

    async def send_command(
        self,
        item_code: int,
        payload: bytes,
        encrypt: bool = True,
        wait_for_response: bool = True,
    ) -> bytes:
        """Sends a structured request and awaits the result response."""
        async with self._send_lock:
            # Build request payload: [item_code] + [payload]
            msg = bytes([item_code]) + payload

            if encrypt:
                if not self._cipher:
                    raise SesameAuthenticationError("Not logged in (cipher is missing)")
                msg = self._cipher.encrypt_payload(msg)

            if not self._client or not self._client.is_connected:
                raise SesameConnectionError("Not connected")

            packets = self._segmenter.segment_payload(msg, encrypt)

            if not wait_for_response:
                for packet in packets:
                    await self._client.write_gatt_char(TX_CHAR_UUID, packet, response=False)
                return b""

            fut = asyncio.get_running_loop().create_future()
            self._pending_responses[item_code] = fut

            try:
                for packet in packets:
                    await self._client.write_gatt_char(TX_CHAR_UUID, packet, response=False)
                return await asyncio.wait_for(fut, timeout=5.0)
            except TimeoutError as err:
                self._pending_responses.pop(item_code, None)
                raise SesameCommandError(
                    f"Timeout waiting for response to item {item_code}", error_code=-1
                ) from err
            except asyncio.CancelledError as err:
                self._pending_responses.pop(item_code, None)
                raise SesameConnectionError("Command cancelled: connection lost") from err
            except Exception:
                self._pending_responses.pop(item_code, None)
                raise


class SesameLock(SesameDevice):
    """Subclass representing a Sesame smart lock (Sesame 3/4/5/5 Pro/6/6 Pro/Bike)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.battery_voltage: float | None = None
        self.battery_percentage: int | None = None
        self.target_angle: int | None = None
        self.current_angle: int | None = None
        self.is_locked: bool | None = None
        self.is_unlocked: bool | None = None
        self.is_moving: bool | None = None
        self.is_battery_critical: bool | None = None
        self.lock_position: int | None = None
        self.unlock_position: int | None = None
        self.auto_lock_second: int | None = None
        self.door_status: str | None = None
        self.ops_lock_second: int | None = None

    def on_published(self, item_code: int, payload: bytes) -> None:
        if item_code == ITEM_MECH_STATUS:
            # Struct: battery (uint16_t), target (int16_t), position (int16_t), flags (uint8_t)
            raw_battery, target, position, flags = struct.unpack("<HhhB", payload[:7])

            self.battery_voltage = raw_battery * 2 / 1000
            self.battery_percentage = calculate_battery_percentage(self.battery_voltage)
            self.target_angle = target
            self.current_angle = position

            self.is_locked = bool(flags & 0x02)
            self.is_unlocked = bool(flags & 0x04)
            self.is_moving = not bool(flags & 0x10)
            self.is_battery_critical = bool(flags & 0x20)

            self.mech_status = self
            if not self._login_event.is_set():
                self._login_event.set()

            if self._status_cb:
                self._status_cb(self, self)

        elif item_code == ITEM_MECH_SETTING:
            if len(payload) >= 4:
                lock_pos, unlock_pos = struct.unpack("<hh", payload[0:4])
                self.lock_position = lock_pos
                self.unlock_position = unlock_pos
            if len(payload) >= 6:
                self.auto_lock_second = struct.unpack("<H", payload[4:6])[0]
            # We must receive mech setting to complete registration/login flow event
            if not self._login_event.is_set():
                self._login_event.set()

            if self._status_cb:
                self._status_cb(self, self)

        elif item_code == ITEM_DOOR_OPEN:
            self.door_status = "open"
            if self._status_cb:
                self._status_cb(self, self)

        elif item_code == ITEM_DOOR_CLOSED:
            self.door_status = "closed"
            if self._status_cb:
                self._status_cb(self, self)

        elif item_code == ITEM_OPS_TIMER_SETTING:
            if len(payload) >= 2:
                self.ops_lock_second = struct.unpack("<H", payload[0:2])[0]
            if self._status_cb:
                self._status_cb(self, self)

    async def lock(self, history_name: str = "Home Assistant") -> None:
        """Locks the Sesame device."""
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        name_bytes = history_name.encode("utf-8")[:20]
        payload = bytes([len(name_bytes)]) + name_bytes
        await self.send_command(ITEM_LOCK, payload, encrypt=True)

    async def unlock(self, history_name: str = "Home Assistant") -> None:
        """Unlocks the Sesame device."""
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        name_bytes = history_name.encode("utf-8")[:20]
        payload = bytes([len(name_bytes)]) + name_bytes
        await self.send_command(ITEM_UNLOCK, payload, encrypt=True)

    async def configure_lock_position(self, lock_position: int, unlock_position: int) -> None:
        """Configures the lock and unlock angle thresholds."""
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        payload = struct.pack("<hh", lock_position, unlock_position)
        logger.info(
            "Configuring lock positions [address=%s, lock=%d, unlock=%d]",
            self.address,
            lock_position,
            unlock_position,
        )
        await self.send_command(ITEM_MECH_SETTING, payload, encrypt=True)

    async def set_auto_lock_second(self, second: int) -> None:
        """Configures the automatic locking timer in seconds."""
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        payload = struct.pack("<H", second)
        logger.info(
            "Configuring auto lock duration [address=%s, seconds=%d]",
            self.address,
            second,
        )
        await self.send_command(ITEM_AUTOLOCK, payload, encrypt=True)

    async def set_ops_lock_second(self, second: int) -> None:
        """Configures the OpenSensor auto lock duration in seconds."""
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        payload = struct.pack("<H", second)
        logger.info(
            "Configuring OpenSensor auto lock duration [address=%s, seconds=%d]",
            self.address,
            second,
        )
        await self.send_command(ITEM_OPS_TIMER_SETTING, payload, encrypt=True)

    async def calibrate_magnet(self) -> None:
        """Triggers the lock to perform magnet calibration/angle correction."""
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        logger.info("Triggering magnet calibration [address=%s]", self.address)
        await self.send_command(ITEM_MAGNET, b"", encrypt=True)

    async def fetch_and_flush_history(self) -> list[dict[str, Any]]:
        """Fetch and flush all available history records from the lock."""
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")

        records: list[dict[str, Any]] = []
        while True:
            try:
                payload = await self.send_command(ITEM_HISTORY, b"\x01", encrypt=True)
                if len(payload) < 16:
                    break

                record_id, history_type, ts, _mech_status = struct.unpack("<IBI7s", payload[:16])

                tag = 0
                raw_val = b""

                if len(payload) > 16:
                    param_bytes = payload[16:]
                    if len(param_bytes) >= 2:
                        tag = struct.unpack("<H", param_bytes[0:2])[0]
                        if len(param_bytes) >= 3:
                            data_length = min(max(0, param_bytes[2]), len(param_bytes) - 3)
                            raw_val = param_bytes[3 : 3 + data_length]

                record = {
                    "record_id": record_id,
                    "type": history_type,
                    "timestamp": ts,
                    "tag": tag,
                    "raw_parameter": raw_val.hex(),
                }
                records.append(record)
                await self.send_command(ITEM_HISTORY_DELETE, payload[0:4], encrypt=True)

            except Exception as e:
                if (isinstance(e, SesameCommandError) and e.error_code == 5) or "5" in str(e):
                    # 5 = CMD_RESULT_NOT_FOUND (queue empty)
                    break
                logger.exception("Error during history fetch/flush loop: %s", e)
                raise

        return records


def parse_dt(dt_str: str) -> datetime.datetime | None:
    """Parse an ISO format datetime string safely."""
    if not dt_str:
        return None
    try:
        return datetime.datetime.fromisoformat(dt_str)
    except Exception:
        return None


class BaseKeypad:
    """Generic interface/base class for keypads with credential management and scheduling."""

    def __init__(self) -> None:
        self.passcodes: dict[str, dict[str, Any]] = {}
        self.cards: dict[str, dict[str, Any]] = {}
        self.fingerprints: dict[str, dict[str, Any]] = {}
        self.faces: dict[str, dict[str, Any]] = {}
        self.palms: dict[str, dict[str, Any]] = {}
        self.cards_count = 0
        self.fingerprints_count = 0
        self.passcodes_count = 0
        self.faces_count = 0
        self.palms_count = 0

    async def get_passcodes(self) -> dict[str, dict[str, Any]]:
        """Fetch/sync passcodes from the keypad."""
        raise NotImplementedError

    async def add_passcode(self, code: str, name: str) -> None:
        """Add a new passcode to the keypad."""
        raise NotImplementedError

    async def delete_passcode(self, code_or_id: str) -> None:
        """Delete an existing passcode from the keypad."""
        raise NotImplementedError

    async def update_passcode_name(self, code_or_id: str, name: str) -> None:
        """Update the nickname of an existing passcode on the keypad."""
        raise NotImplementedError

    async def get_cards(self) -> dict[str, dict[str, Any]]:
        """Fetch/sync cards from the keypad."""
        raise NotImplementedError

    async def delete_card(self, card_id: str) -> None:
        """Delete a card from the keypad."""
        raise NotImplementedError

    async def update_card_name(self, card_id: str, name: str) -> None:
        """Update the nickname of an existing card on the keypad."""
        raise NotImplementedError

    async def get_fingerprints(self) -> dict[str, dict[str, Any]]:
        """Fetch/sync fingerprints from the keypad."""
        raise NotImplementedError

    async def delete_fingerprint(self, finger_id: str) -> None:
        """Delete a fingerprint from the keypad."""
        raise NotImplementedError

    async def update_fingerprint_name(self, finger_id: str, name: str) -> None:
        """Update the nickname of an existing fingerprint on the keypad."""
        raise NotImplementedError

    async def get_faces(self) -> dict[str, dict[str, Any]]:
        """Fetch/sync faces from the keypad."""
        raise NotImplementedError

    async def delete_face(self, face_id: str) -> None:
        """Delete a face from the keypad."""
        raise NotImplementedError

    async def update_face_name(self, face_id: str, name: str) -> None:
        """Update the nickname of an existing face on the keypad."""
        raise NotImplementedError

    async def get_palms(self) -> dict[str, dict[str, Any]]:
        """Fetch/sync palms from the keypad."""
        raise NotImplementedError

    async def delete_palm(self, palm_id: str) -> None:
        """Delete a palm from the keypad."""
        raise NotImplementedError

    async def update_palm_name(self, palm_id: str, name: str) -> None:
        """Update the nickname of an existing palm on the keypad."""
        raise NotImplementedError

    async def apply_passcode_schedules(self, logical_passcodes: dict[str, dict[str, Any]]) -> bool:
        """Evaluates schedules and synchronizes passcodes.

        This implements the virtualization of time-windowed passcodes by checking
        start/end times, weekly day lists, and daily time ranges, adding or
        deleting passcodes accordingly.

        Returns:
            bool: True if any changes were made, False otherwise.
        """
        now = datetime.datetime.now()
        changed = False

        for uid, logical_info in list(logical_passcodes.items()):
            # 1. Absolute date/time range check
            start_dt = parse_dt(logical_info.get("start", ""))
            end_dt = parse_dt(logical_info.get("end", ""))

            should_be_active = True
            if start_dt and now < start_dt:
                should_be_active = False
            if end_dt and now >= end_dt:
                should_be_active = False

            # 2. Weekly days check
            days_list = logical_info.get("days")
            if should_be_active and days_list:
                try:
                    int_days = [int(d) for d in days_list]
                    if now.weekday() not in int_days:
                        should_be_active = False
                except (ValueError, TypeError) as err:
                    logger.warning(
                        "Invalid days list for passcode '%s': %s",
                        logical_info.get("name"),
                        err,
                    )

            # 3. Daily time range check
            time_start_str = str(logical_info.get("time_start", "")).strip()
            time_end_str = str(logical_info.get("time_end", "")).strip()
            if should_be_active and (time_start_str or time_end_str):
                current_time = now.time()
                if time_start_str:
                    try:
                        h, m = map(int, time_start_str.split(":"))
                        if current_time < datetime.time(h, m):
                            should_be_active = False
                    except (ValueError, TypeError) as err:
                        logger.warning(
                            "Invalid time_start '%s' for passcode '%s': %s",
                            time_start_str,
                            logical_info.get("name"),
                            err,
                        )
                if time_end_str:
                    try:
                        h, m = map(int, time_end_str.split(":"))
                        if current_time >= datetime.time(h, m):
                            should_be_active = False
                    except (ValueError, TypeError) as err:
                        logger.warning(
                            "Invalid time_end '%s' for passcode '%s': %s",
                            time_end_str,
                            logical_info.get("name"),
                            err,
                        )

            is_physically_active = uid in self.passcodes

            if should_be_active and not is_physically_active:
                logger.info(
                    "Scheduler: Adding passcode '%s' via virtualization",
                    logical_info.get("name"),
                )
                try:
                    await self.add_passcode(logical_info["code"], str(logical_info.get("name", "")))
                    changed = True
                except Exception as err:
                    logger.error(
                        "Failed to add passcode '%s': %s",
                        logical_info.get("name"),
                        err,
                    )
            elif not should_be_active and is_physically_active:
                logger.info(
                    "Scheduler: Removing passcode '%s' via virtualization",
                    logical_info.get("name"),
                )
                try:
                    await self.delete_passcode(uid)
                    changed = True
                except Exception as err:
                    logger.error(
                        "Failed to delete passcode '%s': %s",
                        logical_info.get("name"),
                        err,
                    )

        return changed


class SesameKeypad(SesameDevice, BaseKeypad):
    """Subclass representing a Sesame Touch, Touch Pro, Face, or Face Pro keypad."""

    def __init__(
        self,
        ble_device: BLEDevice | None,
        ad_data: SesameAdData | None = None,
        secret_key: str | bytes | None = None,
        status_callback: Callable[[object, object], None] | None = None,
        reconnect_attempts: int = 0,
    ) -> None:
        super().__init__(
            ble_device,
            ad_data,
            secret_key=secret_key,
            status_callback=status_callback,
            reconnect_attempts=reconnect_attempts,
        )
        BaseKeypad.__init__(self)
        self.passcodes: dict[str, dict[str, Any]] = {}
        self.cards: dict[str, dict[str, Any]] = {}
        self.fingerprints: dict[str, dict[str, Any]] = {}
        self.faces: dict[str, dict[str, Any]] = {}
        self.palms: dict[str, dict[str, Any]] = {}

        self.cards_count = 0
        self.fingerprints_count = 0
        self.passcodes_count = 0
        self.faces_count = 0
        self.palms_count = 0

        self._temp_passcodes: dict[str, dict[str, Any]] = {}
        self._temp_cards: dict[str, dict[str, Any]] = {}
        self._temp_fingerprints: dict[str, dict[str, Any]] = {}
        self._temp_faces: dict[str, dict[str, Any]] = {}
        self._temp_palms: dict[str, dict[str, Any]] = {}

        self._sync_future: asyncio.Future[bool] | None = None
        self.scanned_fingerprint: dict[str, Any] | None = None
        self.scanned_passcode: dict[str, Any] | None = None
        self.scanned_card: dict[str, Any] | None = None
        self.scanned_face: dict[str, Any] | None = None
        self.scanned_palm: dict[str, Any] | None = None
        self.paired_locks: list[dict[str, Any]] = []

        self.card_registration_mode = False
        self.fingerprint_registration_mode = False
        self.passcode_registration_mode = False
        self.face_registration_mode = False
        self.palm_registration_mode = False

        self.battery_voltage: float | None = None
        self.battery_percentage: int | None = None
        self.is_battery_critical: bool | None = None

    def on_published(self, item_code: int, payload: bytes) -> None:
        if item_code == ITEM_MECH_STATUS:
            faces = 0
            palms = 0
            if len(payload) == 7:
                raw_battery, cards, fingerprints, passwords, flags = struct.unpack(
                    "<HhBBB", payload
                )
            elif len(payload) >= 9:
                model_id = getattr(getattr(self, "ad_data", None), "model_id", None) or getattr(
                    self, "product_model", None
                )
                if is_face_keypad_model(model_id):
                    raw_battery, cards, fingerprints, passwords, faces, palms, flags = (
                        struct.unpack("<HhBBBBB", payload[:9])
                    )
                else:
                    raw_battery, cards, fingerprints, passwords, flags = struct.unpack(
                        "<HhhhB", payload[:9]
                    )
            else:
                return

            self.battery_voltage = raw_battery * 2 / 1000
            self.battery_percentage = calculate_battery_percentage(self.battery_voltage)
            self.cards_count = cards
            self.fingerprints_count = fingerprints
            self.passcodes_count = passwords
            self.faces_count = faces
            self.palms_count = palms
            self.is_battery_critical = bool(flags & 0x20)

            self.mech_status = self
            if not self._login_event.is_set():
                self._login_event.set()

            if self._status_cb:
                self._status_cb(self, self)

        elif item_code == ITEM_PASSCODE_FIRST:
            self._temp_passcodes = {}

        elif item_code == ITEM_PASSCODE_NOTIFY:
            parsed = self._parse_notify_payload(payload, is_passcode=True)
            self._temp_passcodes.update(parsed)
            for uid, info in parsed.items():
                is_new = uid not in self.passcodes
                if self._sync_future is None or (
                    getattr(self, "passcode_registration_mode", False) and is_new
                ):
                    self.scanned_passcode = {
                        "uid": uid,
                        "code": info["code"],
                        "type": info["type"],
                    }
                    if self._status_cb:
                        self._status_cb(self, self)

        elif item_code == ITEM_PASSCODE_LAST:
            self.passcodes = self._temp_passcodes
            if self._sync_future and not self._sync_future.done():
                self._sync_future.set_result(True)

        elif item_code == ITEM_CARD_FIRST:
            self._temp_cards = {}

        elif item_code == ITEM_CARD_NOTIFY:
            parsed = self._parse_notify_payload(payload, is_passcode=False)
            self._temp_cards.update(parsed)
            for uid, info in parsed.items():
                is_new = uid not in self.cards
                if self._sync_future is None or (
                    getattr(self, "card_registration_mode", False) and is_new
                ):
                    self.scanned_card = {
                        "uid": uid,
                        "type": info["type"],
                    }
                    if self._status_cb:
                        self._status_cb(self, self)

        elif item_code == ITEM_CARD_LAST:
            self.cards = self._temp_cards
            if self._sync_future and not self._sync_future.done():
                self._sync_future.set_result(True)

        elif item_code == ITEM_FINGER_FIRST:
            self._temp_fingerprints = {}

        elif item_code == ITEM_FINGER_NOTIFY:
            parsed = self._parse_notify_payload(payload, is_passcode=False)
            self._temp_fingerprints.update(parsed)
            for uid, info in parsed.items():
                is_new = uid not in self.fingerprints
                if self._sync_future is None or (
                    getattr(self, "fingerprint_registration_mode", False) and is_new
                ):
                    self.scanned_fingerprint = {
                        "uid": uid,
                        "type": info["type"],
                    }
                    if self._status_cb:
                        self._status_cb(self, self)

        elif item_code == ITEM_FINGER_LAST:
            self.fingerprints = self._temp_fingerprints
            if self._sync_future and not self._sync_future.done():
                self._sync_future.set_result(True)

        elif item_code == ITEM_FACE_FIRST:
            self._temp_faces = {}

        elif item_code == ITEM_FACE_NOTIFY:
            parsed = self._parse_notify_payload(payload, is_passcode=False)
            self._temp_faces.update(parsed)
            for uid, info in parsed.items():
                is_new = uid not in self.faces
                if self._sync_future is None or (
                    getattr(self, "face_registration_mode", False) and is_new
                ):
                    self.scanned_face = {"uid": uid, "type": info["type"]}
                    if self._status_cb:
                        self._status_cb(self, self)

        elif item_code == ITEM_FACE_LAST:
            self.faces = self._temp_faces
            if self._sync_future and not self._sync_future.done():
                self._sync_future.set_result(True)

        elif item_code == ITEM_PALM_FIRST:
            self._temp_palms = {}

        elif item_code == ITEM_PALM_NOTIFY:
            parsed = self._parse_notify_payload(payload, is_passcode=False)
            self._temp_palms.update(parsed)
            for uid, info in parsed.items():
                is_new = uid not in self.palms
                if self._sync_future is None or (
                    getattr(self, "palm_registration_mode", False) and is_new
                ):
                    self.scanned_palm = {"uid": uid, "type": info["type"]}
                    if self._status_cb:
                        self._status_cb(self, self)

        elif item_code == ITEM_PALM_LAST:
            self.palms = self._temp_palms
            if self._sync_future and not self._sync_future.done():
                self._sync_future.set_result(True)

        elif item_code == ITEM_KEYPAD_LOCK_LIST:
            self._parse_paired_locks(payload)

        elif item_code == ITEM_PASSCODE_VERIFY_TO_CLOUD:
            if len(payload) >= 2:
                kb_type = payload[0]
                id_len = payload[1]
                if len(payload) >= 2 + id_len:
                    kb_id = payload[2 : 2 + id_len]
                    code_str = "".join(str(b) for b in kb_id)
                    self.scanned_passcode = {
                        "uid": kb_id.hex(),
                        "code": code_str,
                        "type": kb_type,
                    }
                    if self._status_cb:
                        self._status_cb(self, self)

        elif item_code == ITEM_CARD_VERIFY_TO_CLOUD:
            if len(payload) >= 2:
                card_type = payload[0]
                id_len = payload[1]
                if len(payload) >= 2 + id_len:
                    card_id = payload[2 : 2 + id_len]
                    self.scanned_card = {
                        "uid": card_id.hex(),
                        "type": card_type,
                    }
                    if self._status_cb:
                        self._status_cb(self, self)

    async def _sync_credentials(
        self, cmd: int, count: int, temp_attr: str, final_attr: str
    ) -> dict[str, dict[str, Any]]:
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        if count == 0:
            setattr(self, final_attr, {})
            return getattr(self, final_attr)

        fut = self._sync_future = asyncio.get_running_loop().create_future()
        setattr(self, temp_attr, {})
        try:
            await self.send_command(cmd, b"", encrypt=True, wait_for_response=False)
            await asyncio.wait_for(fut, timeout=15.0)
            return getattr(self, final_attr)
        finally:
            if self._sync_future is fut:
                self._sync_future = None

    async def _delete_credential(self, cmd: int, id_bytes: bytes) -> None:
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        await self.send_command(cmd, id_bytes, encrypt=True)

    async def _update_credential_name(self, cmd: int, id_bytes: bytes, name: str) -> None:
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        name_bytes = name.encode("utf-8")[:20]
        payload = bytes([len(id_bytes)]) + id_bytes + name_bytes
        await self.send_command(cmd, payload, encrypt=True)

    async def _set_mode(self, cmd: int, active: bool) -> None:
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        mode = 0x01 if active else 0x00
        await self.send_command(cmd, bytes([mode]), encrypt=True)

    async def get_passcodes(self) -> dict[str, dict[str, Any]]:
        """Syncs the passcode database from the keypad and returns it."""
        return await self._sync_credentials(
            ITEM_PASSCODE_GET, self.passcodes_count, "_temp_passcodes", "passcodes"
        )

    def _resolve_code(self, code_or_id: str) -> bytes:
        code_str = str(code_or_id).strip()
        if code_str in self.passcodes:
            return bytes.fromhex(code_str)

        for uid, info in self.passcodes.items():
            if isinstance(info, dict):
                c = str(info.get("code", "")).strip()
                if c == code_str or (code_str.isdigit() and c == code_str.zfill(6)):
                    return bytes.fromhex(uid)

        if (
            len(code_str) % 2 == 0
            and len(code_str) >= 8
            and all(code_str[i] == "0" for i in range(0, len(code_str), 2))
            and all(code_str[i].isdigit() for i in range(1, len(code_str), 2))
        ):
            return bytes.fromhex(code_str)

        if code_str.isdigit():
            padded_6 = code_str.zfill(6)
            padded_hex = bytes(int(c) for c in padded_6).hex()
            if padded_hex in self.passcodes:
                return bytes.fromhex(padded_hex)
            return bytes(int(c) for c in code_str)

        raise ValueError(f"Invalid passcode formatting: {code_or_id}")

    async def add_passcode(self, code: str, name: str) -> None:
        """Adds a passcode PIN to the keypad."""
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")

        id_bytes = self._resolve_code(code)
        if len(id_bytes) < 4 or len(id_bytes) > 16:
            raise ValueError("Passcode must be between 4 and 16 digits")

        name_bytes = name.encode("utf-8")[:20]
        payload = bytearray(40)
        payload[0] = 0xF0  # KB_DATA_USED
        payload[1] = 0x00  # KB_TYPE_LOCAL
        payload[2] = len(id_bytes)
        payload[3 : 3 + len(id_bytes)] = id_bytes
        payload[19] = len(name_bytes)
        payload[20 : 20 + len(name_bytes)] = name_bytes

        await self.send_command(ITEM_PASSCODE_ADD, bytes(payload), encrypt=True)

    async def delete_passcode(self, code_or_id: str) -> None:
        """Deletes a passcode PIN or Hex ID from the keypad."""
        await self._delete_credential(ITEM_PASSCODE_DELETE, self._resolve_code(code_or_id))

    async def update_passcode_name(self, code_or_id: str, name: str) -> None:
        """Updates the nickname of an existing passcode."""
        await self._update_credential_name(
            ITEM_PASSCODE_CHANGE, self._resolve_code(code_or_id), name
        )

    def _parse_notify_payload(
        self, payload: bytes, is_passcode: bool = False
    ) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        idx = 0
        while idx + 3 <= len(payload):
            item_type = payload[idx]
            id_len = payload[idx + 1]
            if idx + 2 + id_len > len(payload):
                break
            item_id = payload[idx + 2 : idx + 2 + id_len]
            name_len = payload[idx + 2 + id_len]
            if idx + 2 + id_len + 1 + name_len > len(payload):
                break
            name_bytes = payload[idx + 2 + id_len + 1 : idx + 2 + id_len + 1 + name_len]

            name = None
            if len(name_bytes) == 16:
                try:
                    val = UUID(bytes=name_bytes)
                    if val.version == 4:
                        name = f"App Code ({str(val)[:8]})"
                except ValueError:
                    pass

            if name is None:
                name = name_bytes.decode("utf-8", errors="replace").rstrip("\x00")

            if is_passcode:
                code_str = "".join(str(b) for b in item_id)
            else:
                code_str = item_id.hex()

            results[item_id.hex()] = {
                "name": name,
                "code": code_str,
                "type": item_type,
            }
            idx += 2 + id_len + 1 + name_len
        return results

    async def get_cards(self) -> dict[str, dict[str, Any]]:
        """Syncs the card database from the keypad and returns it."""
        return await self._sync_credentials(ITEM_CARD_GET, self.cards_count, "_temp_cards", "cards")

    async def delete_card(self, card_id: str) -> None:
        """Deletes a card from the keypad."""
        await self._delete_credential(ITEM_CARD_DELETE, bytes.fromhex(card_id))

    async def update_card_name(self, card_id: str, name: str) -> None:
        """Updates the nickname of an existing card."""
        await self._update_credential_name(ITEM_CARD_CHANGE, bytes.fromhex(card_id), name)

    async def add_card(self, card_id: str, name: str, card_type: int = 0x80) -> None:
        """Registers/Adds a card to the keypad database."""
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")

        card_id_bytes = bytes.fromhex(card_id)
        card_name_bytes = name.encode("utf-8")[:20]
        payload = bytearray(40)
        payload[0] = 0xF0
        payload[1] = card_type
        payload[2] = len(card_id_bytes)
        payload[3 : 3 + len(card_id_bytes)] = card_id_bytes
        payload[19] = len(card_name_bytes)
        payload[20 : 20 + len(card_name_bytes)] = card_name_bytes

        await self.send_command(ITEM_CARD_ADD, bytes(payload), encrypt=True)

    async def get_fingerprints(self) -> dict[str, dict[str, Any]]:
        """Syncs the fingerprint database from the keypad and returns it."""
        return await self._sync_credentials(
            ITEM_FINGER_GET, self.fingerprints_count, "_temp_fingerprints", "fingerprints"
        )

    async def delete_fingerprint(self, finger_id: str) -> None:
        """Deletes a fingerprint from the keypad."""
        await self._delete_credential(ITEM_FINGER_DELETE, bytes.fromhex(finger_id))

    async def update_fingerprint_name(self, finger_id: str, name: str) -> None:
        """Updates the nickname of an existing fingerprint."""
        await self._update_credential_name(ITEM_FINGER_CHANGE, bytes.fromhex(finger_id), name)

    async def set_card_registration_mode(self, active: bool) -> None:
        """Sets the keypad card mode: True for Add Mode, False for Verification Mode."""
        await self._set_mode(ITEM_CARD_MODE_SET, active)
        self.card_registration_mode = active

    async def set_fingerprint_registration_mode(self, active: bool) -> None:
        """Sets the keypad fingerprint mode: True for Add Mode, False for Verification Mode."""
        await self._set_mode(ITEM_FINGER_MODE_SET, active)
        self.fingerprint_registration_mode = active

    async def set_passcode_registration_mode(self, active: bool) -> None:
        """Sets the keypad passcode mode: True for Add Mode, False for Verification Mode."""
        await self._set_mode(ITEM_PASSCODE_MODE_SET, active)
        self.passcode_registration_mode = active

    async def get_faces(self) -> dict[str, dict[str, Any]]:
        """Syncs the face database from the keypad and returns it."""
        return await self._sync_credentials(ITEM_FACE_GET, self.faces_count, "_temp_faces", "faces")

    async def delete_face(self, face_id: str) -> None:
        """Deletes a face from the keypad."""
        await self._delete_credential(ITEM_FACE_DELETE, bytes.fromhex(face_id))

    async def update_face_name(self, face_id: str, name: str) -> None:
        """Updates the nickname of an existing face."""
        await self._update_credential_name(ITEM_FACE_CHANGE, bytes.fromhex(face_id), name)

    async def set_face_registration_mode(self, active: bool) -> None:
        """Sets the keypad face mode: True for Add Mode, False for Verification Mode."""
        await self._set_mode(ITEM_FACE_MODE_SET, active)
        self.face_registration_mode = active

    async def get_palms(self) -> dict[str, dict[str, Any]]:
        """Syncs the palm database from the keypad and returns it."""
        return await self._sync_credentials(ITEM_PALM_GET, self.palms_count, "_temp_palms", "palms")

    async def delete_palm(self, palm_id: str) -> None:
        """Deletes a palm from the keypad."""
        await self._delete_credential(ITEM_PALM_DELETE, bytes.fromhex(palm_id))

    async def update_palm_name(self, palm_id: str, name: str) -> None:
        """Updates the nickname of an existing palm."""
        await self._update_credential_name(ITEM_PALM_CHANGE, bytes.fromhex(palm_id), name)

    async def set_palm_registration_mode(self, active: bool) -> None:
        """Sets the keypad palm mode: True for Add Mode, False for Verification Mode."""
        await self._set_mode(ITEM_PALM_MODE_SET, active)
        self.palm_registration_mode = active

    def _parse_paired_locks(self, payload: bytes) -> None:
        if len(payload) < 69:
            return

        paired = []
        for i in range(3):
            offset = i * 23
            name_bytes = payload[offset : offset + 22]
            status_byte = payload[offset + 22]

            uuid_obj = self._parse_base64_uuid(name_bytes)
            if uuid_obj and status_byte != 0:
                paired.append(
                    {
                        "uuid": str(uuid_obj),
                        "status": status_byte,
                    }
                )
        self.paired_locks = paired
        if self._status_cb:
            self._status_cb(self, self)

    def _parse_base64_uuid(self, name_bytes: bytes) -> UUID | None:
        binary_bytes = name_bytes.rstrip(b"\x00")
        if len(binary_bytes) == 16:
            try:
                return UUID(bytes=binary_bytes)
            except ValueError:
                pass

        try:
            clean = name_bytes.rstrip(b"\x00").decode("ascii").strip()
            if not clean:
                return None
            padding = "=" * (4 - len(clean) % 4)
            uuid_bytes = base64.b64decode(clean + padding)
            if len(uuid_bytes) == 16:
                return UUID(bytes=uuid_bytes)
        except Exception:
            pass
        return None

    async def add_paired_lock(self, device_uuid: UUID, secret_key: bytes) -> None:
        """Add/Pair a Sesame Lock to the keypad."""
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        payload = device_uuid.bytes + secret_key
        await self.send_command(ITEM_ADD_SESAME, payload, encrypt=True)

    async def remove_paired_lock(self, device_uuid: UUID) -> None:
        """Remove/Unpair a Sesame Lock from the keypad."""
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        await self.send_command(ITEM_REMOVE_SESAME, device_uuid.bytes, encrypt=True)


class SesameBot(SesameDevice):
    """Subclass representing a Sesame Bot switch pusher."""

    async def click(self) -> None:
        """Triggers a click action."""
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        await self.send_command(ITEM_LOCK, b"", encrypt=True)

    async def lock(self) -> None:
        """Triggers a lock/press action."""
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        await self.send_command(ITEM_LOCK, b"", encrypt=True)

    async def unlock(self) -> None:
        """Triggers an unlock/retract action."""
        if not self.is_logged_in:
            raise SesameAuthenticationError("Device is not logged in")
        await self.send_command(ITEM_UNLOCK, b"", encrypt=True)


class SesameOpenSensor(SesameDevice):
    """Subclass representing a Sesame Open Sensor contact sensor."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.door_status: str | None = None

    def on_published(self, item_code: int, payload: bytes) -> None:
        if item_code == ITEM_DOOR_OPEN:
            self.door_status = "open"
            if self._status_cb:
                self._status_cb(self, self)
        elif item_code == ITEM_DOOR_CLOSED:
            self.door_status = "closed"
            if self._status_cb:
                self._status_cb(self, self)


class SesameBikeLock(SesameLock):
    """Subclass representing a Sesame Bike Lock."""


def create_sesame_device(
    ble_device: BLEDevice | None,
    ad_data: SesameAdData | None = None,
    secret_key: str | bytes | None = None,
    **kwargs: Any,
) -> SesameDevice:
    """Factory function to instantiate the appropriate Sesame device class."""
    if ad_data:
        if is_keypad_model(ad_data.model_id):
            return SesameKeypad(ble_device, ad_data, secret_key=secret_key, **kwargs)
        if is_bot_model(ad_data.model_id):
            return SesameBot(ble_device, ad_data, secret_key=secret_key, **kwargs)
        if is_open_sensor_model(ad_data.model_id):
            return SesameOpenSensor(ble_device, ad_data, secret_key=secret_key, **kwargs)
        if is_bike_lock_model(ad_data.model_id):
            return SesameBikeLock(ble_device, ad_data, secret_key=secret_key, **kwargs)
    return SesameLock(ble_device, ad_data, secret_key=secret_key, **kwargs)


async def scan_sesame_devices(
    timeout: float = 5.0,
    callback: Callable[[BLEDevice, SesameAdData], None] | None = None,
) -> dict[str, tuple[BLEDevice, SesameAdData]]:
    """Scan for nearby Sesame BLE devices."""
    found_devices: dict[str, tuple[BLEDevice, SesameAdData]] = {}

    def detection_callback(device: BLEDevice, advertisement_data: Any) -> None:
        mfg_dict = advertisement_data.manufacturer_data
        mfg = get_sesame_mfg_data(mfg_dict) if mfg_dict else None
        if not mfg:
            return
        _, raw_data = mfg
        try:
            ad_data = SesameAdData.decode(raw_data)
            if device.address not in found_devices:
                found_devices[device.address] = (device, ad_data)
                if callback:
                    callback(device, ad_data)
        except Exception:
            pass

    scanner = BleakScanner(detection_callback=detection_callback)
    try:
        await scanner.start()
        await asyncio.sleep(timeout)
    finally:
        await scanner.stop()
    return found_devices


async def find_sesame_device(
    address: str,
    timeout: float = 5.0,
) -> tuple[BLEDevice, SesameAdData | None] | None:
    """Find a specific Sesame BLE device by MAC address."""
    target_addr = address.upper()
    found_event = asyncio.Event()
    found_ble_device: BLEDevice | None = None
    found_ad_data: SesameAdData | None = None

    def detection_callback(device: BLEDevice, adv: Any) -> None:
        nonlocal found_ble_device, found_ad_data
        if device.address.upper() == target_addr:
            found_ble_device = device
            if adv.manufacturer_data:
                mfg = get_sesame_mfg_data(adv.manufacturer_data)
                if mfg:
                    with contextlib.suppress(Exception):
                        found_ad_data = SesameAdData.decode(mfg[1])
            found_event.set()

    scanner = BleakScanner(detection_callback=detection_callback)
    try:
        await scanner.start()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(found_event.wait(), timeout=timeout)
    finally:
        await scanner.stop()

    if not found_ble_device:
        found_ble_device = await BleakScanner.find_device_by_address(address, timeout=timeout)

    if not found_ble_device:
        return None

    return found_ble_device, found_ad_data
