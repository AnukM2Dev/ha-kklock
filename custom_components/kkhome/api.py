"""Async API client for KK Home."""

from __future__ import annotations

import asyncio
from base64 import b64decode, b64encode, urlsafe_b64decode
from dataclasses import dataclass
import json
import logging
import time
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from httpx import HTTPError

from homeassistant.helpers.httpx_client import get_async_client

from .ble import KKHomeBleController, KKHomeBleError, KKHomeBleUnavailableError
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_BASE_URL,
    CONF_DEVICE_DETAIL_PATH,
    CONF_DEVICES_PATH,
    CONF_LOCK_PATH,
    CONF_LOGIN_PATH,
    CONF_PASSWORD,
    CONF_STATUS_PATH,
    CONF_TENANT_ID,
    CONF_UNLOCK_PATH,
    CONF_USERNAME,
)

_LOGGER = logging.getLogger(__name__)

_APP_PRIVATE_KEY = b64decode(
    "MIICXgIBAAKBgQC7M6FvIfDuzM3/QHcYKz5LcPcBm3829kb2UCH/GJThmMjiPqWQzN7Zzh666lSnWIB1mPa6xLQMRUsd/eNH68fWTYcrqnBXunVgkf56ppD9QZTf4y8IbEAetWiyGDp/4rVG3nsPKXYQTFgN59gzZ++qdtAehsGaC+dce96cNcvowQIDAQABAoGAXDGtS6IXmkPbH96LyKdjYpwbyfreyB66DAyi8ZMVn5UzOdlIiOucxP+yOrO1RUVc3o2a1ZiSY4is2fRzvrPsElMVQaX/wxCF73dqeJvZ8w2Y5izaR04DO5Q3GReVAupXjS0aGuWVzik+w+oTzGxKr9JE5ZFT/de94dULxRzMvAECQQDiSikSfTYv7fHhknfOVhgSJ4lKsgj48x5Bb3MONIJl1yRnYVm8NnXzg7Zga7CurhyLTqaZl6Wz0QiepIFy0sHxAkEA08euJNXW0sMT+Qc3XXXiHITBDjCBHRyjX0xsIf3pcRwBPhgG90jGGuyKOJYNZhu8U/mV9CGd9JBVrlq73RHD0QJBAKs1swejJslyvWyO9ghuiT3LHgwe0b0RrNWTbjjUL8i/03JIbK2DgxCgme8v63jukPgxpMlWvG9le6EUFED9BvECQQCVEgInlYoQcxZ0/TpghCDz+BI4XbYUetsYsp+O0b7nSlIplhoZKFWiEAw/RogJ7s4CwjVmUd9wjcRx5RZFx0JxAkEA0g9KjPzq+duwEnqADu6ls0fzTD8rpkYzukxlNSAFdHMVLnXoRlbmAqS3VcnNkcDJOkYTWXLxPuMGbf4YT0f3BA=="
)
_SERVICE_PUBLIC_KEY = b64decode(
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAhvfVLGrJ/M3xpUnT1xlN30E1UESxhAmGmFyTx3p3vpxF4zMYpUjwHckCvg/zvZwhNTgsm3CNT7LAdE8lCl2YK4BoUZ6IYbbXSOa02/brASX4kjpOPbTcaDfYud2CFWQba95d5dlf3Jf9Z3eTPwNK7YQ0LDDWMOQ6LxoGqcLciQIDAQAB"
)
_ENCRYPT_DATA_HEADER = "encrypt_data"
_AUTH_REFRESH_SKEW_SECONDS = 300
_APP_VERSION = "3.3.1"
_PHONE_NAME = "iPhone17,1"
_USER_AGENT = "KKHome/3.3.1 (iPhone; iOS 26.3.1; Scale/3.00)"
_COMMAND_STATE_GRACE_SECONDS = 90


class KKHomeApiError(Exception):
    """Raised when the KK Home API returns an error."""


class KKHomeAuthError(KKHomeApiError):
    """Raised when authentication fails."""


@dataclass(slots=True)
class KKHomeLockDevice:
    device_id: str
    name: str
    is_locked: bool | None
    battery_level: int | None
    raw: dict[str, Any]


class KKHomeApiClient:
    def __init__(self, hass, config: dict[str, Any]) -> None:
        self._hass = hass
        self._client = get_async_client(hass)
        self._config = config
        self._token: str | None = config.get(CONF_ACCESS_TOKEN) or None
        if self._token == "":
            self._token = None
        self._token_expires_at = self._decode_token_expiration(self._token)
        self._private_key = serialization.load_der_private_key(_APP_PRIVATE_KEY, password=None)
        self._public_key = serialization.load_der_public_key(_SERVICE_PUBLIC_KEY)
        self._ble = KKHomeBleController(hass)
        self._auth_lock = asyncio.Lock()
        self._command_state_overrides: dict[str, tuple[bool, float]] = {}

    @property
    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "*/*",
            "k-language": "en_US",
            "k-signv": "1.0.0",
            "k-tenant": str(self._config[CONF_TENANT_ID]),
            "k-version": _APP_VERSION,
            "phoneName": _PHONE_NAME,
            "User-Agent": _USER_AGENT,
        }
        if self._token:
            headers["token"] = self._token
        return headers

    async def async_authenticate(self) -> None:
        async with self._auth_lock:
            if self._token and not self._token_needs_refresh():
                return
            username = self._config.get(CONF_USERNAME)
            password = self._config.get(CONF_PASSWORD)
            if not username or not password:
                if self._token:
                    return
                raise KKHomeAuthError("Set an access token or provide a username and password.")
            data = await self._request(
                "post",
                self._config[CONF_LOGIN_PATH],
                json_body=self._encrypt_payload({"mail": username, "password": password}),
                headers={_ENCRYPT_DATA_HEADER: _ENCRYPT_DATA_HEADER},
                allow_unauthenticated=True,
            )
            token = self._find_token(data)
            if not token:
                raise KKHomeAuthError("Login succeeded but no token was found in the response.")
            self._set_token(token)
            _LOGGER.debug("KK Home login ok; token length=%s", len(token))

    async def async_test_connection(self) -> None:
        await self.async_authenticate()
        await self.async_get_locks()

    async def async_get_locks(self) -> list[KKHomeLockDevice]:
        await self.async_authenticate()
        payload = await self._request(
            "post",
            self._config[CONF_DEVICES_PATH],
            json_body=self._sign_payload({}),
        )
        devices = self._extract_devices(payload)
        locks: list[KKHomeLockDevice] = []
        for device in devices:
            if not self._looks_like_lock(device):
                continue
            lock = self._normalize_lock(device)
            if lock is not None:
                locks.append(lock)
        _LOGGER.info("KK Home normalized %s locks from %s records", len(locks), len(devices))
        return locks

    async def async_lock(self, device: KKHomeLockDevice) -> None:
        await self._request(
            "post",
            self._config[CONF_LOCK_PATH],
            json_body=self._encrypt_payload(self._command_payload(device)),
            headers={_ENCRYPT_DATA_HEADER: _ENCRYPT_DATA_HEADER},
        )
        self._remember_command_state(device.device_id, True)

    async def async_unlock(self, device: KKHomeLockDevice) -> None:
        await self._request(
            "post",
            self._config[CONF_UNLOCK_PATH],
            json_body=self._encrypt_payload(self._command_payload(device)),
            headers={_ENCRYPT_DATA_HEADER: _ENCRYPT_DATA_HEADER},
        )
        self._remember_command_state(device.device_id, False)

    async def async_get_open_status(self, device: KKHomeLockDevice) -> Any:
        body = self._sign_payload({"esn": self._device_esn(device)})
        try:
            return await self._request("post", self._config[CONF_DEVICE_DETAIL_PATH], json_body=body)
        except KKHomeApiError:
            return await self._request("post", self._config[CONF_STATUS_PATH], json_body=body)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        allow_unauthenticated: bool = False,
        retry_on_auth_failure: bool = True,
    ) -> Any:
        if (
            not allow_unauthenticated
            and retry_on_auth_failure
            and self._token_needs_refresh()
            and self._credentials_available()
        ):
            await self.async_authenticate()

        url = self._build_url(path)
        request_headers = dict(self._headers)
        if allow_unauthenticated:
            request_headers.pop("token", None)
        if headers:
            request_headers.update(headers)
        if json_body is not None:
            request_headers["Content-Type"] = "application/json"
        try:
            response = await self._client.request(
                method, url, headers=request_headers, params=params, json=json_body
            )
        except HTTPError as err:
            raise KKHomeApiError(f"Request failed for {url}: {err}") from err

        text = response.text
        try:
            parsed: Any = json.loads(text) if text else {}
        except json.JSONDecodeError:
            parsed = text
        if isinstance(parsed, dict) and "encryptData" in parsed:
            parsed = self._decrypt_response(parsed["encryptData"])

        if response.status_code in (401, 403) or (
            isinstance(parsed, dict) and self._response_needs_reauthentication(parsed)
        ):
            if not allow_unauthenticated and retry_on_auth_failure and self._credentials_available():
                _LOGGER.warning("KK Home session rejected for %s; retrying login", url)
                self._clear_token()
                await self.async_authenticate()
                return await self._request(
                    method, path, params=params, json_body=json_body, headers=headers,
                    allow_unauthenticated=False, retry_on_auth_failure=False,
                )
            raise KKHomeAuthError(
                (parsed.get("msg") if isinstance(parsed, dict) else None) or "Not logged in"
            )
        if response.status_code >= 400:
            raise KKHomeApiError(f"Request failed for {url}: HTTP {response.status_code}: {text}")

        if isinstance(parsed, dict):
            if parsed.get("success") is False:
                raise KKHomeApiError(parsed.get("msg") or parsed.get("message") or "API returned success=false")
            if "code" in parsed and parsed["code"] not in (0, 200, "0", "200"):
                raise KKHomeApiError(parsed.get("msg") or parsed.get("message") or f"Unexpected response code {parsed['code']}")
            if "data" in parsed:
                return parsed["data"]
        return parsed

    def _build_url(self, path: str) -> str:
        base_url = self._config[CONF_BASE_URL].rstrip("/")
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{base_url}/{path.lstrip('/')}"

    def _extract_devices(self, payload: Any) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        seen: set[int] = set()

        def walk(node: Any) -> None:
            if isinstance(node, list):
                for item in node:
                    walk(item)
                return
            if not isinstance(node, dict):
                return
            obj_id = id(node)
            if obj_id in seen:
                return
            seen.add(obj_id)
            if self._looks_like_device_record(node):
                found.append(node)
            for key in (
                "records", "rows", "list", "devices", "deviceList", "items", "data",
                "page", "result", "children", "childList", "childDevices", "subDevices",
                "subDeviceList", "bindDevices", "bindList", "gatewayDevices", "lockList", "locks",
            ):
                if key in node:
                    walk(node.get(key))

        walk(payload)
        _LOGGER.info("KK Home extracted %s candidate device records", len(found))
        return found

    def _looks_like_device_record(self, device: dict[str, Any]) -> bool:
        return any(device.get(key) for key in ("esn", "deviceEsn", "wifiSN", "deviceId", "deviceNo", "_id", "did", "mac", "bleMac"))

    def _looks_like_lock(self, device: dict[str, Any]) -> bool:
        haystack = " ".join(
            str(device.get(key, ""))
            for key in (
                "name", "lockNickname", "deviceName", "productName", "deviceType",
                "category", "model", "productModel", "type", "deviceModel", "productCode", "sku",
            )
        ).lower()
        if any(token in haystack for token in ("lock", "door", "veise", "ve0", "ve017", "g1", "kk home", "kkhome", "deadbolt")):
            return True
        if device.get("esn") or device.get("deviceEsn") or device.get("wifiSN"):
            return not any(token in haystack for token in ("hub", "gateway", "plug"))
        return False

    def _normalize_lock(self, device: dict[str, Any]) -> KKHomeLockDevice | None:
        device_id = self._first_value(device, "_id", "deviceId", "id", "did", "deviceNo", "wifiSN", "esn")
        if not device_id:
            return None
        name = self._first_value(device, "lockNickname", "name", "deviceName", "productName") or f"KK Home Lock {device_id}"
        return KKHomeLockDevice(
            device_id=str(device_id),
            name=str(name),
            is_locked=self._effective_locked_state(str(device_id), device),
            battery_level=self._extract_battery(device),
            raw=device,
        )

    def _extract_locked(self, device: dict[str, Any]) -> bool | None:
        for key in ("isLocked", "locked", "lockState", "lockStatus", "status", "doorLockStatus", "openStatus", "state"):
            normalized = self._normalize_lock_state(device.get(key))
            if normalized is not None:
                return normalized
        nested = device.get("statusVO") or device.get("properties") or device.get("stateVO")
        if isinstance(nested, dict):
            return self._extract_locked(nested)
        return None

    def _extract_battery(self, device: dict[str, Any]) -> int | None:
        for key in ("battery", "batteryLevel", "electricQuantity", "power"):
            value = device.get(key)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                return int(value)
            if isinstance(value, str) and value.strip().isdigit():
                return int(value.strip())
        nested = device.get("statusVO") or device.get("properties") or device.get("stateVO")
        if isinstance(nested, dict):
            return self._extract_battery(nested)
        return None

    def _effective_locked_state(self, device_id: str, device: dict[str, Any]) -> bool | None:
        locked = self._extract_locked(device)
        override = self._command_state_overrides.get(device_id)
        if override is None:
            return locked
        desired_locked, expires_at = override
        if time.time() >= expires_at:
            self._command_state_overrides.pop(device_id, None)
            return locked
        if locked is desired_locked:
            self._command_state_overrides.pop(device_id, None)
            return locked
        return desired_locked

    def _find_token(self, payload: Any) -> str | None:
        if isinstance(payload, str) and payload.count(".") >= 2:
            return payload
        if isinstance(payload, dict):
            for key in ("accessToken", "access_token", "token", "bearerToken"):
                value = payload.get(key)
                if isinstance(value, str) and value.count(".") >= 2:
                    return value
            for value in payload.values():
                token = self._find_token(value)
                if token:
                    return token
        if isinstance(payload, list):
            for item in payload:
                token = self._find_token(item)
                if token:
                    return token
        return None

    def _response_needs_reauthentication(self, payload: dict[str, Any]) -> bool:
        code = str(payload.get("code", "")).strip()
        if code in {"401", "403", "444"}:
            return True
        message = " ".join(str(payload.get(key, "")) for key in ("msg", "message", "error", "detail")).lower()
        return any(marker in message for marker in ("not logged in", "login expired", "token expired", "invalid token", "unauthorized", "forbidden"))

    def _credentials_available(self) -> bool:
        return bool(self._config.get(CONF_USERNAME) and self._config.get(CONF_PASSWORD))

    def _remember_command_state(self, device_id: str, desired_locked: bool) -> None:
        self._command_state_overrides[device_id] = (desired_locked, time.time() + _COMMAND_STATE_GRACE_SECONDS)

    def _set_token(self, token: str | None) -> None:
        self._token = token or None
        self._token_expires_at = self._decode_token_expiration(self._token)

    def _clear_token(self) -> None:
        self._set_token(None)

    def _token_needs_refresh(self) -> bool:
        if not self._token:
            return True
        if self._token_expires_at is None:
            return False
        return time.time() >= self._token_expires_at - _AUTH_REFRESH_SKEW_SECONDS

    def _decode_token_expiration(self, token: str | None) -> int | None:
        claims = self._decode_jwt_claims(token)
        if not isinstance(claims, dict):
            return None
        expires_at = claims.get("exp")
        if isinstance(expires_at, (int, float)):
            return int(expires_at)
        if isinstance(expires_at, str) and expires_at.isdigit():
            return int(expires_at)
        return None

    def _decode_jwt_claims(self, token: str | None) -> dict[str, Any] | None:
        if not token or token.count(".") < 2:
            return None
        try:
            payload = token.split(".", 2)[1]
            padded = payload + "=" * (-len(payload) % 4)
            claims = json.loads(urlsafe_b64decode(padded.encode()).decode())
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        return claims if isinstance(claims, dict) else None

    def _first_value(self, payload: dict[str, Any], *keys: str) -> Any:
        for key in keys:
            value = payload.get(key)
            if value not in (None, ""):
                return value
        return None

    def _normalize_lock_state(self, value: Any) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            if int(value) == 1:
                return True
            if int(value) in (0, 2):
                return False
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"locked", "lock", "closed", "secure", "1", "true"}:
                return True
            if normalized in {"unlocked", "unlock", "open", "ajar", "0", "2", "false"}:
                return False
        return None

    def _device_esn(self, device: KKHomeLockDevice) -> str:
        esn = self._first_value(device.raw, "wifiSN", "esn", "deviceSn", "sn")
        if esn:
            return str(esn)
        raise KKHomeApiError(f"Device {device.device_id} does not expose an ESN/wifiSN")

    def _command_payload(self, device: KKHomeLockDevice) -> dict[str, Any]:
        user_number_id = self._first_value(device.raw, "userNumberId")
        payload = {"esn": self._device_esn(device)}
        if user_number_id is not None:
            payload["userNumberId"] = int(user_number_id)
        return payload

    def _sign_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        signed_payload = dict(payload)
        signed_payload["reqTime"] = str(int(time.time() * 1000))
        sorted_json = json.dumps(signed_payload, sort_keys=True, separators=(",", ":"))
        signature = self._private_key.sign(sorted_json.encode(), padding.PKCS1v15(), hashes.SHA256())
        signed_payload["sign"] = b64encode(signature).decode()
        return signed_payload

    def _encrypt_payload(self, payload: dict[str, Any]) -> dict[str, str]:
        signed_payload = self._sign_payload(payload)
        payload_bytes = json.dumps(signed_payload, separators=(",", ":")).encode()
        block_size = (self._public_key.key_size // 8) - 11
        encrypted_chunks = [
            self._public_key.encrypt(payload_bytes[offset : offset + block_size], padding.PKCS1v15())
            for offset in range(0, len(payload_bytes), block_size)
        ]
        return {"encryptData": b64encode(b"".join(encrypted_chunks)).decode()}

    def _decrypt_response(self, encrypted_data: str) -> Any:
        encrypted_bytes = b64decode(encrypted_data)
        block_size = self._private_key.key_size // 8
        decrypted_chunks = [
            self._private_key.decrypt(encrypted_bytes[offset : offset + block_size], padding.PKCS1v15())
            for offset in range(0, len(encrypted_bytes), block_size)
        ]
        return json.loads(b"".join(decrypted_chunks).decode())
