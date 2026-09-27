# pysesame-ble

[![PyPI version](https://img.shields.io/pypi/v/pysesame-ble.svg)](https://pypi.org/project/pysesame-ble/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Versions](https://img.shields.io/pypi/pyversions/pysesame-ble.svg)](https://pypi.org/project/pysesame-ble/)

A fast, 100% local Python library for controlling CANDY HOUSE Sesame smart locks and accessories over Bluetooth Low Energy (BLE) using `bleak` and standard `cryptography`.

## Supported Devices

- **Locks**:
  - Sesame 3, Sesame 4
  - Sesame 5, Sesame 5 Pro, Sesame 5 USA
  - Sesame 6, Sesame 6 Pro, Sesame 6 Pro Sliding Door
  - Sesame Bike Lock 1, Bike Lock 2, Bike Lock 3
- **Keypads & Biometric Readers**:
  - Sesame Touch, Sesame Touch Pro, Sesame Touch 2, Sesame Touch 2 Pro
  - Sesame Face, Sesame Face Pro, Sesame Face 2, Sesame Face 2 Pro
  - Passcode, RFID/NFC Card, Fingerprint, Face, and Palm recognition management
- **Accessories**:
  - Sesame Bot (Switch pusher)
  - Sesame Open Sensor (Door/Window magnet sensor)

## Features

- **100% Local & Offline**: Direct communication over BLE. No cloud, Wi-Fi bridge, or internet access required.
- **Modern Security**: Hardware-accelerated cryptographic handshakes via `cryptography.hazmat` (AES-CCM encryption, AES-CMAC session signing, and NIST P-256 ECDH).
- **Setup & QR Code Parsing**: Parse and generate official `ssm://` QR code URLs exported from the CANDY HOUSE mobile app.
- **Direct BLE Onboarding**: Claim and register reset devices directly over BLE without needing the mobile app.
- **Asynchronous Architecture**: Built on `asyncio`, `bleak`, and `bleak-retry-connector`.

## Installation

```bash
pip install pysesame-ble
```

## Quick Start

### 1. Control a Smart Lock

```python
import asyncio
from uuid import UUID
from bleak import BleakScanner
from pysesame_ble import SesameLock, SesameAdData, find_sesame_device

async def main():
    mac = "AA:BB:CC:DD:EE:FF"
    secret_key = "0123456789abcdef0123456789abcdef"  # 16-byte hex secret key

    # Locate BLE device
    result = await find_sesame_device(mac)
    if not result:
        print("Device not found nearby")
        return
    ble_device, ad_data = result

    lock = SesameLock(ble_device, ad_data=ad_data, secret_key=secret_key)
    await lock.connect()
    await lock.login()

    print(f"Lock Battery: {lock.battery_percentage}% ({lock.battery_voltage}V)")
    print(f"Current Angle: {lock.current_angle}°, Locked: {lock.is_locked}")

    # Unlock the door
    await lock.unlock(history_name="Python Script")

    await asyncio.sleep(3)

    # Lock the door
    await lock.lock(history_name="Python Script")

    await lock.disconnect()

asyncio.run(main())
```

### 2. Parse a Setup QR Code (`ssm://`)

```python
from pysesame_ble import SesameQRCode

qr_url = "ssm://UI?t=sk&sk=...&l=0&n=Front%20Door"
qr = SesameQRCode.from_url(qr_url)

print(f"Device Name: {qr.device_name}")
print(f"Model ID: {qr.model_id}")
print(f"UUID: {qr.device_uuid}")
print(f"Secret Key (Hex): {qr.secret_key.hex()}")
```

### 3. Scan for Nearby Sesame Devices

```python
import asyncio
from pysesame_ble import scan_sesame_devices

async def main():
    devices = await scan_sesame_devices(timeout=5.0)
    for address, (ble_dev, ad_data) in devices.items():
        reg_status = "Registered" if ad_data.is_registered else "Unregistered"
        print(f"[{address}] Model: {ad_data.model_id}, Status: {reg_status}, UUID: {ad_data.device_uuid}")

asyncio.run(main())
```

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
