"""RSA helpers used by the KK Home cloud protocol.

Sign: RSA-PKCS1-v1.5 + SHA-256 over sorted compact JSON.
Encrypt: RSA-PKCS1-v1.5 block encryption of the signed JSON.
"""

from __future__ import annotations

import json
import time
from base64 import b64decode, b64encode
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

APP_PRIVATE_KEY_DER = b64decode(
    "MIICXgIBAAKBgQC7M6FvIfDuzM3/QHcYKz5LcPcBm3829kb2UCH/GJThmMjiPqWQzN7Zzh666lSnWIB1mPa6xLQMRUsd/eNH68fWTYcrqnBXunVgkf56ppD9QZTf4y8IbEAetWiyGDp/4rVG3nsPKXYQTFgN59gzZ++qdtAehsGaC+dce96cNcvowQIDAQABAoGAXDGtS6IXmkPbH96LyKdjYpwbyfreyB66DAyi8ZMVn5UzOdlIiOucxP+yOrO1RUVc3o2a1ZiSY4is2fRzvrPsElMVQaX/wxCF73dqeJvZ8w2Y5izaR04DO5Q3GReVAupXjS0aGuWVzik+w+oTzGxKr9JE5ZFT/de94dULxRzMvAECQQDiSikSfTYv7fHhknfOVhgSJ4lKsgj48x5Bb3MONIJl1yRnYVm8NnXzg7Zga7CurhyLTqaZl6Wz0QiepIFy0sHxAkEA08euJNXW0sMT+Qc3XXXiHITBDjCBHRyjX0xsIf3pcRwBPhgG90jGGuyKOJYNZhu8U/mV9CGd9JBVrlq73RHD0QJBAKs1swejJslyvWyO9ghuiT3LHgwe0b0RrNWTbjjUL8i/03JIbK2DgxCgme8v63jukPgxpMlWvG9le6EUFED9BvECQQCVEgInlYoQcxZ0/TpghCDz+BI4XbYUetsYsp+O0b7nSlIplhoZKFWiEAw/RogJ7s4CwjVmUd9wjcRx5RZFx0JxAkEA0g9KjPzq+duwEnqADu6ls0fzTD8rpkYzukxlNSAFdHMVLnXoRlbmAqS3VcnNkcDJOkYTWXLxPuMGbf4YT0f3BA=="
)
SERVICE_PUBLIC_KEY_DER = b64decode(
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAhvfVLGrJ/M3xpUnT1xlN30E1UESxhAmGmFyTx3p3vpxF4zMYpUjwHckCvg/zvZwhNTgsm3CNT7LAdE8lCl2YK4BoUZ6IYbbXSOa02/brASX4kjpOPbTcaDfYud2CFWQba95d5dlf3Jf9Z3eTPwNK7YQ0LDDWMOQ6LxoGqcLciQIDAQAB"
)

_private_key = serialization.load_der_private_key(APP_PRIVATE_KEY_DER, password=None)
_public_key = serialization.load_der_public_key(SERVICE_PUBLIC_KEY_DER)


def generate_rsa(key_size: int = 2048) -> tuple[bytes, bytes]:
    """Generate a new RSA pair. Not usable against the KK Home cloud."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.PKCS1,
    )
    return private_der, public_der


def sign_payload(payload: dict[str, Any], private_key=_private_key) -> dict[str, Any]:
    body = dict(payload)
    body["reqTime"] = str(int(time.time() * 1000))
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    signature = private_key.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
    body["sign"] = b64encode(signature).decode()
    return body


def encrypt_payload(payload: dict[str, Any], private_key=_private_key, public_key=_public_key) -> dict[str, str]:
    signed = json.dumps(sign_payload(payload, private_key), separators=(",", ":")).encode()
    block = (public_key.key_size // 8) - 11
    chunks = [
        public_key.encrypt(signed[offset : offset + block], padding.PKCS1v15())
        for offset in range(0, len(signed), block)
    ]
    return {"encryptData": b64encode(b"".join(chunks)).decode()}
