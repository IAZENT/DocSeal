"""AES-256-GCM encryption with key wrapping."""

import os
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .envelope import DsealEnvelope


def encrypt_document(
    doc_data: bytes, recipient_cert: x509.Certificate
) -> DsealEnvelope:
    """Encrypt document with recipient's public key using AES-256-GCM."""
    envelope = DsealEnvelope()
    envelope.metadata.algorithms["encryption"] = "AES-256-GCM"
    envelope.metadata.payload_encrypted = True

    # Generate random key and IV
    key = os.urandom(32)  # AES-256
    iv = os.urandom(12)  # GCM IV

    # Encrypt with AES-256-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(doc_data) + encryptor.finalize()
    auth_tag = encryptor.tag

    # Wrap key with recipient's public key (RSA-OAEP)
    recipient_pubkey = recipient_cert.public_key()
    wrapped_key = recipient_pubkey.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )

    # Store: IV (12) + wrapped_key + ciphertext + auth_tag (16)
    envelope.payload = iv + wrapped_key + ciphertext + auth_tag
    envelope.recipient_cert = recipient_cert.public_bytes(serialization.Encoding.PEM)

    return envelope


def decrypt_payload(
    payload: bytes, recipient_key: rsa.RSAPrivateKey
) -> bytes:
    """Decrypt payload using AES-256-GCM."""
    # Parse: IV (12) + wrapped_key (256 for RSA-2048) + ciphertext + tag (16)
    iv = payload[:12]
    wrapped_key = payload[12:268]  # 256 bytes for RSA-2048
    ciphertext_and_tag = payload[268:]
    ciphertext = ciphertext_and_tag[:-16]
    auth_tag = ciphertext_and_tag[-16:]

    # Unwrap key
    key = recipient_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )

    # Decrypt with AES-256-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext
