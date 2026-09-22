# KKLock (KK Home) Home Assistant Integration

Unofficial Home Assistant integration for Veise / KK Home smart locks.

Forked from [dmckeown257/kklocks](https://github.com/dmckeown257/kklocks) with a looser device parser so hub-bound models such as **VE017 + G1** actually create entities.

Not affiliated with Veise, KK Home, Kaadas, or Home Assistant. Use at your own risk.

## What changed in 0.2.0

- Recursively walk the KK Home device-list payload (`children`, `subDevices`, `bindDevices`, `data.result`, etc.)
- Treat VE017 / VE0xx / G1 / ESN-bearing lock records as locks even when the name does not contain the word "lock"
- Skip obvious gateway/plug-only records
- Log how many candidate device records were extracted

## Install (HACS custom repository)

1. HACS → Integrations → Custom repositories
2. URL: `https://github.com/AnukM2Dev/ha-kklock`
3. Category: Integration
4. Install, restart Home Assistant
5. Settings → Devices & Services → Add Integration → **KK Home**

Use the same KK Home email/password as the mobile app.

## Notes

Cloud API is still `https://api.kksecurityhome.com` with tenant `kawden`.

If entities are still missing, enable debug logging for `custom_components.kkhome` and check Settings → System → Logs.
