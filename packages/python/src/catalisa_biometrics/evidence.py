"""OFFLINE verification of the signed evidence (Ed25519), without depending on Catalisa.

    message = f"{sessionId}|{attempt}|{bundleHash}|{signedAt}"
    key     = GET /evidence-keys → publicKeyPem of the signature's keyId
"""

from __future__ import annotations

import base64
import binascii
from typing import Any, Dict, Iterable, Mapping, Union

from . import _ed25519


def evidence_message(session_id: str, attempt: int, bundle_hash: str, signed_at: str) -> str:
    return f"{session_id}|{attempt}|{bundle_hash}|{signed_at}"


def verify_evidence_signature(
    session_id: str,
    attempt: int,
    bundle_hash: str,
    signature: Mapping[str, Any],
    keys: Union[Iterable[Mapping[str, Any]], Mapping[str, str]],
) -> Dict[str, Any]:
    key_id = signature.get("keyId")
    if isinstance(keys, Mapping):
        found = {"keyId": key_id, "publicKeyPem": keys.get(key_id), "retiredAt": None} if key_id in keys else None
    else:
        found = next((k for k in keys if k.get("keyId") == key_id), None)
    if not found or not found.get("publicKeyPem"):
        return {"valid": False, "keyId": key_id, "unknownKey": True, "retiredAt": None}
    valid = False
    if signature.get("alg") == "Ed25519":
        try:
            pub = _ed25519.load_public_key(found["publicKeyPem"])
            sig = base64.b64decode(signature.get("value", ""), validate=True)
            msg = evidence_message(session_id, attempt, bundle_hash, signature.get("signedAt", "")).encode("utf-8")
            valid = _ed25519.verify(pub, msg, sig)
        except (ValueError, binascii.Error):
            valid = False
    return {"valid": valid, "keyId": key_id, "unknownKey": False, "retiredAt": found.get("retiredAt")}
