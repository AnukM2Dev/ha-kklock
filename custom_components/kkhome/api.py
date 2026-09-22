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
from .debug_util import summarize_payload
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
        self._uid: str | None = None

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
        if self._uid:
            headers["uid"] = self._uid
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
                unwrap_data=False,
            )
            token = self._find_token(data)
            if not token:
                keys = list(data.keys()) if isinstance(data, dict) else type(data).__name__
                raise KKHomeAuthError(f"Login succeeded but no token was found. Keys: {keys}")
            self._set_token(token)
            blob = data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), dict) else data
            if isinstance(blob, dict) and blob.get("uid"):
                self._uid = str(blob.get("uid"))
                _LOGGER.warning("KK Home login uid=%s token_len=%s", self._uid, len(token))

    async def async_test_connection(self) -> None:
        await self.async_authenticate()
        await self.async_get_locks()

    async def async_get_locks(self) -> list[KKHomeLockDevice]:
        await self.async_authenticate()
        path = self._config[CONF_DEVICES_PATH]
        last_error: Exception | None = None
        payload: Any = None
        attempts = (
            ("no-body", None, None),
            ("signed-uid", self._sign_payload({"uid": self._uid} if self._uid else {}), None),
            ("signed-page", self._sign_payload({"pageNum": 1, "pageSize": 50}), None),
            ("signed-empty", self._sign_payload({}), None),
        )
        for label, body, extra_headers in attempts:
            try:
                kwargs: dict[str, Any] = {}
                if body is not None:
                    kwargs["json_body"] = body
                if extra_headers:
                    kwargs["headers"] = extra_headers
                payload = await self._request("post", path, **kwargs)
                _LOGGER.warning("KK Home device list succeeded via %s", label)
                break
            except KKHomeApiError as err:
                last_error = err
                _LOGGER.warning("KK Home device list %s failed: %s", label, err)
        else:
            raise last_error or KKHomeApiError("Device list failed")
        devices = self._extract_devices(payload)
        locks = []
        for device in devices:
            if not self._looks_like_lock(device):
                continue
            lock = self._normalize_lock(device)
            if lock is not None:
                locks.append(lock)
        _LOGGER.info("KK Home normalized %s locks from %s records", len(locks), len(devices))
        return locks
