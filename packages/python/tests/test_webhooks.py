"""Vetor produzido pelo CÓDIGO DO BB (scripts/gen-vectors.bb.ts → src/webhooks-engine/utils/crypto.ts)."""

import base64
from datetime import datetime

import pytest

from catalisa_biometrics import WebhookVerificationError, check_webhook, construct_event, verify_webhook
from catalisa_biometrics import _rsa


def _now(w):
    return datetime.fromisoformat(w["now"].replace("Z", "+00:00")).timestamp()


def _sent(w):
    return datetime.fromisoformat(w["headers"]["x-webhook-timestamp"].replace("Z", "+00:00")).timestamp()


def test_aceita_entrega_assinada_pelo_bb(vectors):
    w = vectors["webhook"]
    assert verify_webhook(w["body"].encode("utf-8"), w["headers"], w["keys"], now=_now(w))
    assert verify_webhook(w["body"], w["headers"], w["keys"], now=_now(w))


def test_headers_com_caixa_diferente_e_lista(vectors):
    w = vectors["webhook"]
    upper = {k.title(): v for k, v in w["headers"].items()}
    assert verify_webhook(w["body"], upper, w["keys"], now=_now(w))
    as_list = {k: [v] for k, v in w["headers"].items()}
    assert verify_webhook(w["body"], as_list, w["keys"], now=_now(w))


def test_chave_como_pem_unico_e_como_lista(vectors):
    w = vectors["webhook"]
    key_id, pem = next(iter(w["keys"].items()))
    assert verify_webhook(w["body"], w["headers"], pem, now=_now(w))
    assert verify_webhook(w["body"], w["headers"], [{"keyId": key_id, "publicKey": pem}], now=_now(w))


def test_recusa_corpo_adulterado_e_reserializado(vectors):
    w = vectors["webhook"]
    assert check_webhook(w["tamperedBody"], w["headers"], w["keys"], now=_now(w)) == "INVALID_SIGNATURE"
    import json

    pretty = json.dumps(json.loads(w["body"]), indent=2, ensure_ascii=False)
    assert not verify_webhook(pretty, w["headers"], w["keys"], now=_now(w))


def test_id_e_timestamp_fazem_parte_da_mensagem(vectors):
    w = vectors["webhook"]
    h = dict(w["headers"], **{"x-webhook-id": "msg_outro"})
    assert check_webhook(w["body"], h, w["keys"], now=_now(w)) == "INVALID_SIGNATURE"
    h = dict(w["headers"], **{"x-webhook-timestamp": "2026-09-18T15:00:01.000Z"})
    assert check_webhook(w["body"], h, w["keys"], now=_now(w)) == "INVALID_SIGNATURE"


@pytest.mark.parametrize("delta,ok", [(299, True), (301, False), (-301, False)])
def test_tolerancia(vectors, delta, ok):
    w = vectors["webhook"]
    assert verify_webhook(w["body"], w["headers"], w["keys"], now=_sent(w) + delta) is ok


def test_tolerancia_configuravel(vectors):
    w = vectors["webhook"]
    assert verify_webhook(w["body"], w["headers"], w["keys"], now=_sent(w) + 3600, tolerance_seconds=3601)


def test_motivos(vectors):
    w = vectors["webhook"]
    n = _now(w)
    assert check_webhook(w["body"], dict(w["headers"], **{"x-webhook-key-id": "whk_x"}), w["keys"], now=n) == "UNKNOWN_KEY_ID"
    v2 = w["headers"]["x-webhook-signature"].replace("v1=", "v2=", 1)
    assert check_webhook(w["body"], dict(w["headers"], **{"x-webhook-signature": v2}), w["keys"], now=n) == "UNSUPPORTED_SIGNATURE_VERSION"
    sem = {k: v for k, v in w["headers"].items() if k != "x-webhook-id"}
    assert check_webhook(w["body"], sem, w["keys"], now=n) == "MISSING_HEADERS"
    assert check_webhook(w["body"], dict(w["headers"], **{"x-webhook-timestamp": "ontem"}), w["keys"], now=n) == "TIMESTAMP_INVALID"
    assert check_webhook(w["body"], dict(w["headers"], **{"x-webhook-signature": "v1=@@@"}), w["keys"], now=n) == "INVALID_SIGNATURE"


def test_assinatura_com_um_bit_trocado(vectors):
    w = vectors["webhook"]
    raw = bytearray(base64.b64decode(w["headers"]["x-webhook-signature"][3:]))
    raw[-1] ^= 1
    h = dict(w["headers"], **{"x-webhook-signature": "v1=" + base64.b64encode(bytes(raw)).decode()})
    assert not verify_webhook(w["body"], h, w["keys"], now=_now(w))


def test_construct_event(vectors):
    w = vectors["webhook"]
    ev = construct_event(w["body"].encode(), w["headers"], w["keys"], now=_now(w))
    assert ev["type"] == "biometrics.session.completed"
    assert ev["data"]["outcome"] == "APPROVED"
    with pytest.raises(WebhookVerificationError) as e:
        construct_event(w["tamperedBody"], w["headers"], w["keys"], now=_now(w))
    assert e.value.code == "INVALID_SIGNATURE"
    assert e.value.status == 400


def test_rsa_parser_recusa_chave_que_nao_e_rsa(vectors):
    ed_pem = vectors["evidence"]["evidenceKeysResponse"]["data"][0]["publicKeyPem"]
    with pytest.raises(ValueError):
        _rsa.load_public_key(ed_pem)
