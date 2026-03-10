from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_der_public_key


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}")


def _get_header(headers: Mapping[str, Any], name: str) -> str | None:
    direct = headers.get(name)
    if isinstance(direct, str):
        return direct

    lower = headers.get(name.lower())
    if isinstance(lower, str):
        return lower

    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == name.lower() and isinstance(value, str):
            return value

    return None


@dataclass
class MoltSIMProfile:
    version: str
    carrier: str
    agent_id: str
    molt_number: str
    carrier_call_base: str
    public_key: str
    carrier_public_key: str
    signature_algorithm: str
    private_key: str | None = None
    nation_type: str | None = None
    inbox_url: str | None = None
    task_reply_url: str | None = None
    task_cancel_url: str | None = None
    presence_url: str | None = None
    canonical_string: str | None = None
    timestamp_window_seconds: int = 300
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MoltSIMProfile":
        required = [
            "version",
            "carrier",
            "agent_id",
            "molt_number",
            "carrier_call_base",
            "public_key",
            "carrier_public_key",
            "signature_algorithm",
        ]

        missing = [field_name for field_name in required if not data.get(field_name)]
        if missing:
            raise ValueError(f"MoltSIM missing required field(s): {', '.join(missing)}")

        if data["signature_algorithm"] != "Ed25519":
            raise ValueError(
                f"Unsupported signature algorithm: {data['signature_algorithm']}"
            )

        known_fields = {
            "version",
            "carrier",
            "agent_id",
            "molt_number",
            "carrier_call_base",
            "public_key",
            "carrier_public_key",
            "signature_algorithm",
            "private_key",
            "nation_type",
            "inbox_url",
            "task_reply_url",
            "task_cancel_url",
            "presence_url",
            "canonical_string",
            "timestamp_window_seconds",
        }
        extra = {key: value for key, value in data.items() if key not in known_fields}

        return cls(
            version=str(data["version"]),
            carrier=str(data["carrier"]),
            agent_id=str(data["agent_id"]),
            molt_number=str(data["molt_number"]),
            carrier_call_base=str(data["carrier_call_base"]),
            public_key=str(data["public_key"]),
            carrier_public_key=str(data["carrier_public_key"]),
            signature_algorithm=str(data["signature_algorithm"]),
            private_key=data.get("private_key"),
            nation_type=data.get("nation_type"),
            inbox_url=data.get("inbox_url"),
            task_reply_url=data.get("task_reply_url"),
            task_cancel_url=data.get("task_cancel_url"),
            presence_url=data.get("presence_url"),
            canonical_string=data.get("canonical_string"),
            timestamp_window_seconds=int(data.get("timestamp_window_seconds", 300)),
            extra=extra,
        )


@dataclass
class VerifyResult:
    trusted: bool
    carrier_verified: bool
    attestation: str | None = None
    reason: str | None = None


def parse_moltsim(raw_json: str) -> MoltSIMProfile:
    return MoltSIMProfile.from_dict(json.loads(raw_json))


class MoltClient:
    def __init__(self, profile: MoltSIMProfile, strict_mode: bool = True) -> None:
        self.profile = profile
        self.strict_mode = strict_mode

    def verify_inbound(
        self,
        headers: Mapping[str, Any],
        body: str,
        orig_number: str = "anonymous",
    ) -> VerifyResult:
        signature = _get_header(headers, "X-Molt-Identity")
        carrier = _get_header(headers, "X-Molt-Identity-Carrier")
        attestation = _get_header(headers, "X-Molt-Identity-Attest")
        timestamp = _get_header(headers, "X-Molt-Identity-Timestamp")

        if not signature or not carrier or not attestation or not timestamp:
            if self.strict_mode:
                return VerifyResult(
                    trusted=False,
                    carrier_verified=False,
                    reason="Missing carrier identity headers (X-Molt-Identity)",
                )
            return VerifyResult(trusted=True, carrier_verified=False)

        if carrier != self.profile.carrier:
            return VerifyResult(
                trusted=False,
                carrier_verified=False,
                reason=(
                    f"Carrier domain mismatch: expected {self.profile.carrier}, got {carrier}"
                ),
            )

        try:
            ts = int(timestamp)
        except ValueError:
            return VerifyResult(
                trusted=False,
                carrier_verified=False,
                reason="Carrier identity timestamp out of window",
            )

        now = int(time.time())
        if abs(now - ts) > self.profile.timestamp_window_seconds:
            return VerifyResult(
                trusted=False,
                carrier_verified=False,
                reason="Carrier identity timestamp out of window",
            )

        body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        canonical = "\n".join(
            [
                carrier,
                attestation,
                orig_number,
                self.profile.molt_number,
                timestamp,
                body_hash,
            ]
        )

        try:
            public_key = load_der_public_key(_b64url_decode(self.profile.carrier_public_key))
            signature_bytes = _b64url_decode(signature)
            public_key.verify(signature_bytes, canonical.encode("utf-8"))
        except (InvalidSignature, TypeError, ValueError):
            return VerifyResult(
                trusted=False,
                carrier_verified=False,
                reason="Carrier identity signature mismatch",
            )

        return VerifyResult(
            trusted=True,
            carrier_verified=True,
            attestation=attestation,
        )
