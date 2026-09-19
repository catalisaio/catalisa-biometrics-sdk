import json

import pytest

from catalisa_biometrics import (
    APIConnectionError,
    AuthenticationError,
    Biometrics,
    BiometricsError,
    HttpResponse,
    NotFoundError,
    PermissionDeniedError,
    QuotaExceededError,
    RateLimitError,
    ServerError,
    SubaccountSuspendedError,
    ValidationError,
)

ENVELOPE = {
    "sessionId": "5b0e2f4a-1c3d-4e5f-8a9b-0c1d2e3f4a5b",
    "status": "SESSION_OPEN",
    "attempt": 0,
    "handoff": {"captureUrl": "https://biometrics.bb.stg.catalisa.app/biometrics/capture/eyJ", "captureToken": "eyJ"},
}


class FakeTransport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body, "timeout": timeout})
        r = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(r, Exception):
            raise r
        return r


def resp(status, body, headers=None):
    return HttpResponse(status, headers or {"Content-Type": "application/json"}, json.dumps(body).encode())


def test_cria_sessao_com_x_api_key_e_base_padrao():
    t = FakeTransport(resp(201, {"data": ENVELOPE}))
    bio = Biometrics("pk.sk", transport=t)
    s = bio.sessions.create(flow="LIVENESS_ONLY", purpose="abertura de conta", metadata={"canal": "app"})
    assert s["handoff"]["captureUrl"].startswith("https://")
    c = t.calls[0]
    assert (c["method"], c["url"]) == ("POST", "https://api.biometrics.catalisa.app/v1/sessions")
    assert c["headers"]["X-API-Key"] == "pk.sk"
    assert json.loads(c["body"]) == {"flow": "LIVENESS_ONLY", "purpose": "abertura de conta", "metadata": {"canal": "app"}}


def test_base_url_subconta_token_e_idempotency_key():
    t = FakeTransport(resp(201, {"data": ENVELOPE}))
    bio = Biometrics(access_token="jwt", base_url="https://biometrics.bb.stg.catalisa.app/biometrics/api/v1/", subaccount_id="sub-1", transport=t)
    bio.sessions.create(flow="LIVENESS_ONLY", purpose="abc", idempotency_key="pedido-1")
    c = t.calls[0]
    assert c["url"] == "https://biometrics.bb.stg.catalisa.app/biometrics/api/v1/sessions"
    assert c["headers"]["Authorization"] == "Bearer jwt"
    assert "X-API-Key" not in c["headers"]
    assert c["headers"]["X-Subaccount-Id"] == "sub-1"
    assert c["headers"]["Idempotency-Key"] == "pedido-1"


def test_exige_credencial():
    with pytest.raises(ValueError):
        Biometrics()


def test_caminhos():
    t = FakeTransport(resp(200, {"data": ENVELOPE}))
    bio = Biometrics("k", transport=t)
    bio.sessions.get("a/b")
    bio.sessions.cancel("id1")
    bio.sessions.evidence("id1")
    bio.sessions.verify_evidence_on_server("id1")
    bio.evidence.keys()
    base = "https://api.biometrics.catalisa.app/v1"
    assert [(c["method"], c["url"].replace(base, "")) for c in t.calls] == [
        ("GET", "/sessions/a%2Fb"),
        ("POST", "/sessions/id1/cancel"),
        ("GET", "/sessions/id1/evidence"),
        ("GET", "/sessions/id1/evidence/verify"),
        ("GET", "/evidence-keys"),
    ]


def test_list_query():
    t = FakeTransport(resp(200, {"data": [ENVELOPE], "meta": {"total": 1, "page": {"number": 2, "size": 10}}}))
    r = Biometrics("k", transport=t).sessions.list(page=2, page_size=10, status="APPROVED", subaccount_id="s1")
    assert r["meta"]["total"] == 1
    url = t.calls[0]["url"]
    assert "page%5Bnumber%5D=2" in url and "page%5Bsize%5D=10" in url and "status=APPROVED" in url and "subaccountId=s1" in url
    assert "flow=" not in url


@pytest.mark.parametrize(
    "status,body,klass,code",
    [
        (401, {"error": "UNAUTHORIZED", "message": "Invalid API key", "details": {"code": "API_KEY_INVALID"}}, AuthenticationError, "API_KEY_INVALID"),
        (402, {"error": "PAYMENT_REQUIRED", "message": "Cota", "details": {"code": "QUOTA_EXCEEDED", "monthlyQuota": 5, "used": 5}}, QuotaExceededError, "QUOTA_EXCEEDED"),
        (403, {"error": "FORBIDDEN", "message": "Suspensa", "details": {"code": "SUBACCOUNT_SUSPENDED"}}, SubaccountSuspendedError, "SUBACCOUNT_SUSPENDED"),
        (403, {"error": "FORBIDDEN", "message": "Insufficient permissions"}, PermissionDeniedError, "FORBIDDEN"),
        (400, {"error": "VALIDATION", "details": {}}, ValidationError, "VALIDATION"),
        (404, {"error": "NOT_FOUND", "message": "x"}, NotFoundError, "NOT_FOUND"),
    ],
)
def test_erros_tipados(status, body, klass, code):
    t = FakeTransport(resp(status, body, {"X-Trace-Id": "tr-9"}))
    with pytest.raises(klass) as e:
        Biometrics("k", transport=t, sleep=lambda s: None).sessions.create(flow="LIVENESS_ONLY", purpose="abc")
    assert isinstance(e.value, BiometricsError)
    assert e.value.code == code and e.value.status == status and e.value.request_id == "tr-9"


def test_quota_details():
    t = FakeTransport(resp(402, {"error": "PAYMENT_REQUIRED", "message": "m", "details": {"code": "QUOTA_EXCEEDED", "monthlyQuota": 5, "used": 5}}))
    with pytest.raises(QuotaExceededError) as e:
        Biometrics("k", transport=t).sessions.create(flow="LIVENESS_ONLY", purpose="abc")
    assert e.value.details["used"] == 5


def test_429_formato_do_limitador():
    t = FakeTransport(resp(429, {"error": "too_many_requests", "error_description": "Rate limit exceeded.", "retry_after": 7}, {"Retry-After": "7"}))
    with pytest.raises(RateLimitError) as e:
        Biometrics("k", transport=t, max_retries=0).sessions.get("x")
    assert e.value.retry_after == 7 and e.value.message == "Rate limit exceeded."


def test_leitura_repete_em_503_e_rede():
    sleeps = []
    t = FakeTransport(resp(503, {"error": "SERVICE_UNAVAILABLE"}), ConnectionResetError("reset"), resp(200, {"data": ENVELOPE}))
    s = Biometrics("k", transport=t, sleep=sleeps.append).sessions.get("x")
    assert s["sessionId"] == ENVELOPE["sessionId"]
    assert len(t.calls) == 3 and len(sleeps) == 2


def test_desiste_apos_max_retries():
    t = FakeTransport(resp(500, {"message": "Internal server error"}))
    with pytest.raises(ServerError):
        Biometrics("k", transport=t, sleep=lambda s: None, max_retries=2).sessions.get("x")
    assert len(t.calls) == 3


def test_criacao_nao_repete_5xx_nem_rede():
    t = FakeTransport(resp(503, {"error": "SERVICE_UNAVAILABLE"}))
    with pytest.raises(ServerError):
        Biometrics("k", transport=t, sleep=lambda s: None).sessions.create(flow="LIVENESS_ONLY", purpose="abc")
    assert len(t.calls) == 1
    t = FakeTransport(TimeoutError("timed out"))
    with pytest.raises(APIConnectionError) as e:
        Biometrics("k", transport=t, sleep=lambda s: None).sessions.create(flow="LIVENESS_ONLY", purpose="abc")
    assert e.value.code == "TIMEOUT" and len(t.calls) == 1


def test_criacao_repete_em_429_com_retry_after():
    sleeps = []
    t = FakeTransport(resp(429, {"error": "too_many_requests"}, {"retry-after": "2"}), resp(201, {"data": ENVELOPE}))
    Biometrics("k", transport=t, sleep=sleeps.append).sessions.create(flow="LIVENESS_ONLY", purpose="abc")
    assert sleeps == [2.0]


def test_evidence_verify_offline(vectors):
    e = vectors["evidence"]
    env = dict(ENVELOPE, sessionId=e["sessionId"], attempt=e["attempt"], evidence={"bundleHash": e["evidence"]["bundleHash"], "signature": e["evidence"]["signature"]})
    t = FakeTransport(resp(200, {"data": env}), resp(200, e["evidenceKeysResponse"]))
    r = Biometrics("k", transport=t).evidence.verify(e["sessionId"])
    assert r["valid"] is True
    assert t.calls[1]["url"].endswith("/evidence-keys")


def test_transporte_urllib_real_contra_servidor_local():
    """O transporte padrão (urllib) contra um HTTP de verdade: 201, 402 e JSON."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n))
            if self.headers.get("X-Subaccount-Id") == "cheia":
                out, code = {"error": "PAYMENT_REQUIRED", "message": "Cota", "details": {"code": "QUOTA_EXCEEDED"}}, 402
            else:
                out, code = {"data": dict(ENVELOPE, purpose=body["purpose"])}, 201
            raw = json.dumps(out).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    srv = HTTPServer(("127.0.0.1", 0), H)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        base = f"http://127.0.0.1:{srv.server_port}/v1"
        assert Biometrics("k", base_url=base).sessions.create(flow="LIVENESS_ONLY", purpose="real")["purpose"] == "real"
        with pytest.raises(QuotaExceededError):
            Biometrics("k", base_url=base, subaccount_id="cheia").sessions.create(flow="LIVENESS_ONLY", purpose="x")
    finally:
        srv.shutdown()


def test_transporte_urllib_conexao_recusada_vira_api_connection_error():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(APIConnectionError) as e:
        Biometrics("k", base_url=f"http://127.0.0.1:{port}/v1", max_retries=0).sessions.get("x")
    assert e.value.code == "CONNECTION" and e.value.status == 0
