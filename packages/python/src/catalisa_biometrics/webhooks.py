"""Verification of Catalisa Webhooks Engine deliveries, exactly as the engine signs them:

    message   = x-webhook-id + "\\n" + x-webhook-timestamp + "\\n" + raw body
    signature = RSA-SHA256 (PKCS#1 v1.5), base64, in ``x-webhook-signature: v1=<base64>``
    key       = the subscription's PUBLIC key, selected by ``x-webhook-key-id``

Asymmetric: there is no shared secret. The server does not reject old deliveries; the time
tolerance (default 300 s) is enforced here.
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
    "MISSING_HEADERS": "Missing x-webhook-id, x-webhook-timestamp, x-webhook-key-id or x-webhook-signature header",
    "TIMESTAMP_INVALID": "x-webhook-timestamp is not an ISO 8601 date",
    "TIMESTAMP_OUT_OF_TOLERANCE": "Delivery is outside the time tolerance (possible replay)",
    "UNKNOWN_KEY_ID": "No public key for this x-webhook-key-id",
    "UNSUPPORTED_SIGNATURE_VERSION": "Unsupported signature version (expected v1=)",
    "INVALID_SIGNATURE": "Invalid signature",
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
    """``None`` when the delivery is authentic; otherwise the failure code."""
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
    """``True`` when authentic and within tolerance. Pass the RAW body (bytes as received)."""
    return check_webhook(raw_body, headers, public_keys, tolerance_seconds=tolerance_seconds, now=now) is None


def construct_event(
    raw_body: Union[bytes, str],
    headers: Mapping[str, Any],
    public_keys: PublicKeys,
    *,
    tolerance_seconds: int = 300,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Verifies and returns the event (``id``, ``type``, ``data``, ``metadata``); raises ``WebhookVerificationError``."""
    failure = check_webhook(raw_body, headers, public_keys, tolerance_seconds=tolerance_seconds, now=now)
    if failure:
        raise WebhookVerificationError(_MESSAGES[failure], status=400, code=failure)
    try:
        return json.loads(raw_body)
    except ValueError:
        raise WebhookVerificationError("Webhook body is not JSON", status=400, code="INVALID_JSON") from None
