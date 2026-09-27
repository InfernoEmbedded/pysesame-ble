"""Data models and enums for the sesame-ble library."""

import struct
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from typing import Self
from uuid import UUID

from .const import COMPANY_IDS


class ProductModels(IntEnum):
    """Supported Sesame product hardware models."""

    SESAME3 = 0
    SESAME_BOT1 = 1
    SESAME_BIKE1 = 2
    SESAME4 = 4
    SESAME5 = 5
    SESAME_BIKE2 = 6
    SESAME5_PRO = 7
    SESAME_OPEN_SENSOR1 = 8
    SESAME_TOUCH_PRO = 9
    SESAME_TOUCH = 10
    SESAME_BLE_CONNECTOR = 11
    SESAME5_USA = 16
    SESAME_BOT2 = 14
    SESAME_REMOTE = 15
    SESAME_REMOTE_NANO = 17
    SESAME_FACE_PRO = 18
    SESAME_FACE = 19
    SESAME6 = 20
    SESAME6_PRO = 21
    SESAME_FACE_PRO_AI = 22
    SESAME_FACE_AI = 23
    SESAME_TOUCH_2 = 25
    SESAME_TOUCH_2_PRO = 26
    SESAME_FACE_2 = 27
    SESAME_FACE_2_PRO = 28
    SESAME_FACE_2_AI = 30
    SESAME_FACE_2_PRO_AI = 31
    SESAME6_PRO_SLIDING_DOOR = 32
    SESAME_BIKE3 = 33
    SESAME_OPEN_SENSOR2 = 34


def is_keypad_model(model: str | int | ProductModels | None) -> bool:
    """Return True if model is a keypad/touch/face device."""
    if model is None:
        return False
    if isinstance(model, ProductModels):
        name = model.name
    elif isinstance(model, int):
        try:
            name = ProductModels(model).name
        except ValueError:
            return False
    else:
        name = str(model)
    name_upper = name.upper()
    return any(k in name_upper for k in ("TOUCH", "FACE", "AI", "KEYPAD"))


def is_lock_model(model: str | int | ProductModels | None) -> bool:
    """Return True if model is a smart lock or bike lock."""
    if model is None:
        return False
    if isinstance(model, ProductModels):
        name = model.name
    elif isinstance(model, int):
        try:
            name = ProductModels(model).name
        except ValueError:
            return False
    else:
        name = str(model)
    name_upper = name.upper()
    return any(k in name_upper for k in ("SESAME", "LOCK", "BIKE")) and not is_keypad_model(model)


def is_bot_model(model: str | int | ProductModels | None) -> bool:
    """Return True if model is a Sesame Bot switch pusher."""
    if model is None:
        return False
    if isinstance(model, ProductModels):
        name = model.name
    elif isinstance(model, int):
        try:
            name = ProductModels(model).name
        except ValueError:
            return False
    else:
        name = str(model)
    return "BOT" in name.upper()


def is_open_sensor_model(model: str | int | ProductModels | None) -> bool:
    """Return True if model is a Sesame Open Sensor door/window contact."""
    if model is None:
        return False
    if isinstance(model, ProductModels):
        name = model.name
    elif isinstance(model, int):
        try:
            name = ProductModels(model).name
        except ValueError:
            return False
    else:
        name = str(model)
    return "OPEN_SENSOR" in name.upper()


def is_bike_lock_model(model: str | int | ProductModels | None) -> bool:
    """Return True if model is a Sesame Bike Lock."""
    if model is None:
        return False
    if isinstance(model, ProductModels):
        name = model.name
    elif isinstance(model, int):
        try:
            name = ProductModels(model).name
        except ValueError:
            return False
    else:
        name = str(model)
    return "BIKE" in name.upper()


def get_sesame_mfg_data(mfg_dict: dict[int, bytes]) -> tuple[int, bytes] | None:
    """Finds Sesame/CandyHouse manufacturer data across known company IDs or payloads."""
    if not mfg_dict:
        return None
    for cid in COMPANY_IDS:
        if cid in mfg_dict:
            return cid, mfg_dict[cid]
    # Fallback: check any company ID with >= 19 bytes payload
    for cid, data in mfg_dict.items():
        if len(data) >= 19:
            return cid, data
    return None


VOLTAGE_LEVELS = (
    5.85,
    5.82,
    5.79,
    5.76,
    5.73,
    5.70,
    5.65,
    5.60,
    5.55,
    5.50,
    5.40,
    5.20,
    5.10,
    5.0,
    4.8,
    4.6,
)
BATTERY_PERCENTAGES = (
    100.0,
    95.0,
    90.0,
    85.0,
    80.0,
    70.0,
    60.0,
    50.0,
    40.0,
    32.0,
    21.0,
    13.0,
    10.0,
    7.0,
    3.0,
    0.0,
)


def calculate_battery_percentage(voltage: float) -> int:
    """Calculates estimated battery capacity from voltage using linear interpolation."""
    if voltage >= VOLTAGE_LEVELS[0]:
        return int(BATTERY_PERCENTAGES[0])
    if voltage <= VOLTAGE_LEVELS[-1]:
        return int(BATTERY_PERCENTAGES[-1])
    for i in range(len(VOLTAGE_LEVELS) - 1):
        upper_v = VOLTAGE_LEVELS[i]
        lower_v = VOLTAGE_LEVELS[i + 1]
        if lower_v < voltage <= upper_v:
            ratio = (voltage - lower_v) / (upper_v - lower_v)
            upper_p = BATTERY_PERCENTAGES[i]
            lower_p = BATTERY_PERCENTAGES[i + 1]
            return int((upper_p - lower_p) * ratio + lower_p)
    return 0


@dataclass
class SesameAdData:
    """Decoded manufacturer data from a Sesame BLE advertisement."""

    model_id: int
    is_registered: bool
    device_uuid: UUID

    @classmethod
    def decode(cls, manufacturer_data: bytes) -> Self:
        """Parses raw advertisement bytes (<HB16s)."""
        if len(manufacturer_data) < 19:
            raise ValueError(f"Manufacturer data too short: {len(manufacturer_data)} bytes")
        model_val, registered_val, uuid_bytes = struct.unpack("<HB16s", manufacturer_data[:19])
        return cls(
            model_id=model_val,
            is_registered=bool(registered_val & 1),
            device_uuid=UUID(bytes=uuid_bytes),
        )


@dataclass
class SesameMechStatus:
    """Status state of a Sesame smart lock."""

    battery_voltage: float
    battery_percentage: int
    target_angle: int
    current_angle: int
    is_locked: bool
    is_unlocked: bool
    is_moving: bool
    is_battery_critical: bool
    timestamp: datetime | None = None


@dataclass
class KeypadMechStatus:
    """Status state of a Sesame Touch / Face keypad."""

    battery_voltage: float
    battery_percentage: int
    is_battery_critical: bool
    cards_count: int = 0
    fingerprints_count: int = 0
    passcodes_count: int = 0
    faces_count: int = 0
    palms_count: int = 0
    timestamp: datetime | None = None
