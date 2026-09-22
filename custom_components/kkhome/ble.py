"""BLE transport stub. Cloud control is the supported path for G1-hub locks."""

from __future__ import annotations

from typing import Any


class KKHomeBleError(Exception):
    """Raised when BLE lock control fails."""


class KKHomeBleUnavailableError(KKHomeBleError):
    """Raised when BLE support is unavailable on the host."""


class KKHomeBleController:
    """Placeholder so the cloud client can import BLE types."""

    def __init__(self, hass) -> None:
        self._hass = hass

    async def async_set_lock_state(
        self,
        device: dict[str, Any],
        *,
        currently_locked: bool | None,
    ) -> None:
        raise KKHomeBleUnavailableError("BLE control is not enabled in this build.")
