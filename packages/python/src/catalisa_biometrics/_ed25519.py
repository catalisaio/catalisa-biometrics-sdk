"""Verificação Ed25519 (RFC 8032 §5.1.7) só com a stdlib.

Adaptado do código de referência da RFC 8032 §6 (domínio público). Só VERIFICA — não há
chave privada aqui — então a falta de tempo constante não vaza segredo. Usado para
conferir a evidência assinada do Biometrics sem depender da Catalisa nem de pacote externo.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Optional, Tuple

_p = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p
_SQRT_M1 = pow(2, (_p - 1) // 4, _p)
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

Point = Tuple[int, int, int, int]
_G_Y = 4 * pow(5, _p - 2, _p) % _p


def _add(P: Point, Q: Point) -> Point:
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _mul(s: int, P: Point) -> Point:
    Q: Point = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P: Point, Q: Point) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % _p != 0:
        return False
    return (P[1] * Q[2] - Q[1] * P[2]) % _p == 0


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _p:
        return None
    x2 = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _SQRT_M1 % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


def _decompress(s: bytes) -> Optional[Point]:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _p)


_G: Point = (_recover_x(_G_Y, 0) or 0, _G_Y, 1, (_recover_x(_G_Y, 0) or 0) * _G_Y % _p)


def load_public_key(pem: str) -> bytes:
    """``BEGIN PUBLIC KEY`` SPKI Ed25519 (o que ``GET /evidence-keys`` publica) → 32 bytes."""
    m = re.search(r"-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----", pem, re.S)
    if not m:
        raise ValueError("PEM de chave pública não encontrado")
    der = base64.b64decode("".join(m.group(1).split()))
    if len(der) != 44 or not der.startswith(_ED25519_SPKI_PREFIX):
        raise ValueError("a chave não é Ed25519")
    return der[len(_ED25519_SPKI_PREFIX) :]


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    if A is None:
        return False
    R = _decompress(signature[:32])
    if R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    sB = _mul(s, _G)
    hA = _mul(h, A)
    return _equal(sB, _add(R, hA))
