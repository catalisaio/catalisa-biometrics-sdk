"""RSA-SHA256 verification (PKCS#1 v1.5, RFC 8017 §8.2.2) with the standard library only.

Python's standard library has no RSA. Verifying (not signing) is public arithmetic:
``s^e mod n`` compared with the EMSA-PKCS1-v1_5 encoding of the message's SHA-256.
No secret goes through here, so there is no side channel to protect beyond the final
comparison, which is constant-time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import Tuple

# DER DigestInfo prefix for SHA-256 (RFC 8017 §9.2, note 1)
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
_RSA_OID = bytes.fromhex("2a864886f70d010101")  # 1.2.840.113549.1.1.1


class KeyFormatError(ValueError):
    pass


def _read_len(data: bytes, i: int) -> Tuple[int, int]:
    first = data[i]
    i += 1
    if first < 0x80:
        return first, i
    n = first & 0x7F
    if n == 0 or n > 4:
        raise KeyFormatError("invalid DER length")
    return int.from_bytes(data[i : i + n], "big"), i + n


def _read_tlv(data: bytes, i: int, tag: int) -> Tuple[bytes, int]:
    if i >= len(data) or data[i] != tag:
        raise KeyFormatError("unexpected DER (tag 0x%02x)" % tag)
    length, j = _read_len(data, i + 1)
    end = j + length
    if end > len(data):
        raise KeyFormatError("truncated DER")
    return data[j:end], end


def _parse_rsa_public_key(der: bytes) -> Tuple[int, int]:
    """RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }"""
    seq, _ = _read_tlv(der, 0, 0x30)
    n_bytes, i = _read_tlv(seq, 0, 0x02)
    e_bytes, _ = _read_tlv(seq, i, 0x02)
    return int.from_bytes(n_bytes, "big"), int.from_bytes(e_bytes, "big")


def load_public_key(pem: str) -> Tuple[int, int]:
    """Accepts ``BEGIN PUBLIC KEY`` (SPKI, what the Webhooks Engine publishes) and ``BEGIN RSA PUBLIC KEY``."""
    m = re.search(r"-----BEGIN ((?:RSA )?PUBLIC KEY)-----(.+?)-----END \1-----", pem, re.S)
    if not m:
        raise KeyFormatError("public key PEM not found")
    der = base64.b64decode("".join(m.group(2).split()))
    if m.group(1) == "RSA PUBLIC KEY":
        return _parse_rsa_public_key(der)
    spki, _ = _read_tlv(der, 0, 0x30)
    alg, i = _read_tlv(spki, 0, 0x30)
    oid, _ = _read_tlv(alg, 0, 0x06)
    if oid != _RSA_OID:
        raise KeyFormatError("the key is not RSA")
    bits, _ = _read_tlv(spki, i, 0x03)
    if not bits or bits[0] != 0:
        raise KeyFormatError("invalid BIT STRING")
    return _parse_rsa_public_key(bits[1:])


def verify_pkcs1v15_sha256(message: bytes, signature: bytes, key: Tuple[int, int]) -> bool:
    n, e = key
    k = (n.bit_length() + 7) // 8
    if len(signature) != k or k < len(_SHA256_DIGEST_INFO) + 32 + 11:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = _SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(em, expected)
