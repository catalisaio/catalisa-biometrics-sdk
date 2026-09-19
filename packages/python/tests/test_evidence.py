"""Vector produced by the server's BiometricsEvidenceSignatureService (Ed25519)."""

from catalisa_biometrics import verify_evidence_signature
from catalisa_biometrics import _ed25519


def _args(e, **over):
    a = dict(session_id=e["sessionId"], attempt=e["attempt"], bundle_hash=e["evidence"]["bundleHash"], signature=e["evidence"]["signature"])
    a.update(over)
    return a


def test_verifies_server_signature(vectors):
    e = vectors["evidence"]
    r = verify_evidence_signature(**_args(e), keys=e["evidenceKeysResponse"]["data"])
    assert r == {"valid": True, "keyId": e["evidence"]["signature"]["keyId"], "unknownKey": False, "retiredAt": None}


def test_rejects_changes(vectors):
    e = vectors["evidence"]
    keys = e["evidenceKeysResponse"]["data"]
    assert not verify_evidence_signature(**_args(e, attempt=2), keys=keys)["valid"]
    bh = "ff" + e["evidence"]["bundleHash"][2:]
    assert not verify_evidence_signature(**_args(e, bundle_hash=bh), keys=keys)["valid"]
    sig = dict(e["evidence"]["signature"], signedAt="2026-01-01T00:00:00.000Z")
    assert not verify_evidence_signature(**_args(e, signature=sig), keys=keys)["valid"]
    sig = dict(e["evidence"]["signature"], keyId="ev-other")
    r = verify_evidence_signature(**_args(e, signature=sig), keys=keys)
    assert r["unknownKey"] and not r["valid"]


def test_key_map(vectors):
    e = vectors["evidence"]
    k = e["evidenceKeysResponse"]["data"][0]
    assert verify_evidence_signature(**_args(e), keys={k["keyId"]: k["publicKeyPem"]})["valid"]


def test_rfc8032_vector_1():
    # RFC 8032 §7.1, TEST 1 (empty message)
    pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert _ed25519.verify(pub, b"", sig)
    assert not _ed25519.verify(pub, b"x", sig)
