"""Optional ECC helpers.

KK Home cloud auth remains RSA-PKCS1-v1.5. This module is for local/testing
use only and is not used by the API client.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.exceptions import InvalidSignature


@dataclass(frozen=True)
class EccKeyPair:
    private_pem: bytes
    public_pem: bytes
    curve: str


def generate_p256() -> EccKeyPair:
    key = ec.generate_private_key(ec.SECP256R1())
    return EccKeyPair(
        private_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        public_pem=key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        curve="secp256r1",
    )


def generate_ed25519() -> EccKeyPair:
    key = ed25519.Ed25519PrivateKey.generate()
    return EccKeyPair(
        private_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        public_pem=key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        curve="ed25519",
    )


def sign_p256(private_pem: bytes, message: bytes) -> bytes:
    key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("P-256 signer requires an EC private key")
    return key.sign(message, ec.ECDSA(hashes.SHA256()))


def verify_p256(public_pem: bytes, message: bytes, signature: bytes) -> bool:
    key = serialization.load_pem_public_key(public_pem)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TypeError("P-256 verifier requires an EC public key")
    try:
        key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def sign_ed25519(private_pem: bytes, message: bytes) -> bytes:
    key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError("Ed25519 signer requires an Ed25519 private key")
    return key.sign(message)


def verify_ed25519(public_pem: bytes, message: bytes, signature: bytes) -> bool:
    key = serialization.load_pem_public_key(public_pem)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise TypeError("Ed25519 verifier requires an Ed25519 public key")
    try:
        key.verify(signature, message)
    except InvalidSignature:
        return False
    return True
