"""Verificação das entregas do Webhooks Engine da Catalisa, exatamente como ele assina:

    mensagem   = x-webhook-id + "\\n" + x-webhook-timestamp + "\\n" + corpo cru
    assinatura = RSA-SHA256 (PKCS#1 v1.5), base64, em ``x-webhook-signature: v1=<base64>``
    chave      = a PÚBLICA da subscription, escolhida por ``x-webhook-key-id``

Assimétrica: não há segredo compartilhado. O BB não recusa entrega antiga; a tolerância
de tempo (padrão 300 s) é aplicada aqui.
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from datetime import datetime
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple, Union

from . import _rsa
from .errors import WebhookVerificationError

PublicKeys = Union[str, Mapping[str, str], Iterable[Mapping[str, str]]]

_MESSAGES = {
    "MISSING_HEADERS": "Faltam headers x-webhook-id, x-webhook-timestamp, x-webhook-key-id ou x-webhook-signature",
    "TIMESTAMP_INVALID": "x-webhook-timestamp não é uma data ISO 8601",
    "TIMESTAMP_OUT_OF_TOLERANCE": "Entrega fora da tolerância de tempo (possível replay)",
    "UNKNOWN_KEY_ID": "Nenhuma chave pública para este x-webhook-key-id",
    "UNSUPPORTED_SIGNATURE_VERSION": "Versão de assinatura não suportada (esperado v1=)",
    "INVALID_SIGNATURE": "Assinatura inválida",
}

_key_cache: Dict[str, Tuple[int, int]] = {}


def _header(headers: Mapping[str, Any], name: str) -> Optional[str]:
    v = headers.get(name)
    if v is None:
        for k in headers.keys():
            if str(k).lower() == name:
                v = headers[k]
                break
    if isinstance(v, (list, tuple)):
        v = v[0] if v else None
    return None if v is None else str(v)


def _pem_for(keys: PublicKeys, key_id: str) -> Optional[str]:
    if isinstance(keys, str):
        return keys
    if isinstance(keys, Mapping):
        v = keys.get(key_id)
        return v if isinstance(v, str) else None
    for item in keys:
        if item.get("keyId") == key_id:
            return item.get("publicKey") or item.get("publicKeyPem")
    return None


def _parse_ts(ts: str) -> Optional[float]:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def check_webhook(
    raw_body: Union[bytes, str],
    headers: Mapping[str, Any],
    public_keys: PublicKeys,
    *,
    tolerance_seconds: int = 300,
    now: Optional[float] = None,
) -> Optional[str]:
    """``None`` se a entrega é autêntica; senão o código do motivo."""
    msg_id = _header(headers, "x-webhook-id")
    ts = _header(headers, "x-webhook-timestamp")
    key_id = _header(headers, "x-webhook-key-id")
    sig = _header(headers, "x-webhook-signature")
    if not (msg_id and ts and key_id and sig):
        return "MISSING_HEADERS"
    sent = _parse_ts(ts)
    if sent is None:
        return "TIMESTAMP_INVALID"
    current = time.time() if now is None else now
    if tolerance_seconds > 0 and abs(current - sent) > tolerance_seconds:
        return "TIMESTAMP_OUT_OF_TOLERANCE"
    pem = _pem_for(public_keys, key_id)
    if not pem:
        return "UNKNOWN_KEY_ID"
    if not sig.startswith("v1="):
        return "UNSUPPORTED_SIGNATURE_VERSION"
    try:
        signature = base64.b64decode(sig[3:], validate=True)
    except (binascii.Error, ValueError):
        return "INVALID_SIGNATURE"
    key = _key_cache.get(pem)
    if key is None:
        key = _rsa.load_public_key(pem)
        _key_cache[pem] = key
    body = raw_body.encode("utf-8") if isinstance(raw_body, str) else bytes(raw_body)
    message = f"{msg_id}\n{ts}\n".encode("utf-8") + body
    return None if _rsa.verify_pkcs1v15_sha256(message, signature, key) else "INVALID_SIGNATURE"


def verify_webhook(
    raw_body: Union[bytes, str],
    headers: Mapping[str, Any],
    public_keys: PublicKeys,
    *,
    tolerance_seconds: int = 300,
    now: Optional[float] = None,
) -> bool:
    """``True`` se autêntica e dentro da tolerância. Passe o corpo CRU (bytes recebidos)."""
    return check_webhook(raw_body, headers, public_keys, tolerance_seconds=tolerance_seconds, now=now) is None


def construct_event(
    raw_body: Union[bytes, str],
    headers: Mapping[str, Any],
    public_keys: PublicKeys,
    *,
    tolerance_seconds: int = 300,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Verifica e devolve o evento (``id``, ``type``, ``data``, ``metadata``); lança ``WebhookVerificationError``."""
    failure = check_webhook(raw_body, headers, public_keys, tolerance_seconds=tolerance_seconds, now=now)
    if failure:
        raise WebhookVerificationError(_MESSAGES[failure], status=400, code=failure)
    try:
        return json.loads(raw_body)
    except ValueError:
        raise WebhookVerificationError("Corpo do webhook não é JSON", status=400, code="INVALID_JSON") from None
