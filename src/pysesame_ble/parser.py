"""QR Code parser and generator for Candy House ssm:// setup URLs."""

import base64
import struct
from dataclasses import dataclass
from typing import Self
from urllib import parse
from uuid import UUID

from .exceptions import SesameKeyError


@dataclass(frozen=True)
class SesameQRCode:
    """Decodes and encodes setup QR codes for Sesame devices."""

    device_name: str
    key_level: int
    model_id: int
    device_uuid: UUID
    secret_key: bytes

    @classmethod
    def from_url(cls, url: str) -> Self:
        """Parses a ssm:// setup URL from the Candy House app."""
        parsed = parse.urlparse(url.strip())
        query_raw = parsed.query
        params = dict(parse.parse_qsl(query_raw, keep_blank_values=True))

        sk_str = params.get("sk", "").replace(" ", "+")
        if not sk_str:
            raise SesameKeyError("QR URL is missing secret key 'sk' parameter")

        sk_str += "=" * (-len(sk_str) % 4)

        try:
            key_level = int(params.get("l", "0"))
        except ValueError as err:
            raise SesameKeyError(f"Invalid key level in QR URL: {err}") from err
        device_name = params.get("n", "")

        try:
            shared_key = base64.b64decode(sk_str)
        except Exception as err:
            raise SesameKeyError(f"Failed to decode base64 secret key: {err}") from err

        if len(shared_key) < 39:
            raise SesameKeyError(
                f"Shared key payload too short ({len(shared_key)} bytes, expected 39)"
            )

        # Format: >B16s4s2s16s
        # (Model ID, secret key, token placeholder, index placeholder, UUID bytes)
        model_id, secret_key, _, _, uuid_bytes = struct.unpack(">B16s4s2s16s", shared_key[:39])

        return cls(
            device_name=device_name,
            key_level=key_level,
            model_id=model_id,
            device_uuid=UUID(bytes=uuid_bytes),
            secret_key=secret_key,
        )

    def to_url(self) -> str:
        """Generates a ssm:// setup URL compatible with the official app."""
        shared_key = struct.pack(
            ">B16s4s2s16s",
            self.model_id,
            self.secret_key,
            bytes(4),
            bytes(2),
            self.device_uuid.bytes,
        )
        sk_b64 = base64.b64encode(shared_key).decode("ascii")
        params = parse.urlencode(
            {
                "t": "sk",
                "sk": sk_b64,
                "l": self.key_level,
                "n": self.device_name,
            },
            quote_via=parse.quote,
        )
        return f"ssm://UI?{params}"
