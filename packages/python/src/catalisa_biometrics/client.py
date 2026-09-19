"""Catalisa Biometrics HTTP client, standard library only (urllib)."""

from __future__ import annotations

import json
import random
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional

from .errors import APIConnectionError, BiometricsError, RateLimitError, error_from_response
from .evidence import verify_evidence_signature

DEFAULT_BASE_URL = "https://api.biometrics.catalisa.app/v1"
STAGING_BASE_URL = "https://biometrics.bb.stg.catalisa.app/biometrics/api/v1"
VERSION = "0.1.0"


@dataclass
class HttpResponse:
    status: int
    headers: Dict[str, str]
    body: bytes


#: (method, url, headers, body, timeout) -> HttpResponse. Injectable in tests.
Transport = Callable[[str, str, Dict[str, str], Optional[bytes], float], HttpResponse]


def urllib_transport(method: str, url: str, headers: Dict[str, str], body: Optional[bytes], timeout: float) -> HttpResponse:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:  # noqa: S310 (URL built by the client itself)
            return HttpResponse(res.status, dict(res.headers.items()), res.read())
    except urllib.error.HTTPError as e:
        return HttpResponse(e.code, dict(e.headers.items()) if e.headers else {}, e.read() or b"")


class _Sessions:
    def __init__(self, client: "Biometrics") -> None:
        self._c = client

    def create(self, *, flow: str, purpose: str, idempotency_key: Optional[str] = None, **fields: Any) -> Dict[str, Any]:
        """Opens a session. Extra fields (``subjectRef``, ``reference``, ``customerId``, ``appearance``,
        ``metadata``, ``enrollOnApprove``...) are sent as in the server contract. Returns the envelope
        with ``handoff.captureUrl``. Not retried on 5xx/network errors (avoids duplicate sessions)."""
        body = {"flow": flow, "purpose": purpose, **fields}
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        return self._c._request("POST", "/sessions", body=body, idempotent=False, headers=headers)["data"]

    def get(self, session_id: str) -> Dict[str, Any]:
        """The full envelope (status, decision, checks, evidence)."""
        return self._c._request("GET", f"/sessions/{_enc(session_id)}", idempotent=True)["data"]

    def list(
        self,
        *,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        status: Optional[str] = None,
        flow: Optional[str] = None,
        customer_id: Optional[str] = None,
        subject_cpf: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        subaccount_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """``{"data": [...], "meta": {"total", "page": {"number", "size"}}}``."""
        query = {
            "page[number]": page,
            "page[size]": page_size,
            "status": status,
            "flow": flow,
            "customerId": customer_id,
            "subjectCpf": subject_cpf,
            "from": date_from,
            "to": date_to,
            "subaccountId": subaccount_id,
        }
        return self._c._request("GET", "/sessions", query=query, idempotent=True)

    def cancel(self, session_id: str) -> Dict[str, Any]:
        return self._c._request("POST", f"/sessions/{_enc(session_id)}/cancel", idempotent=False)["data"]

    def evidence(self, session_id: str) -> Dict[str, Any]:
        return self._c._request("GET", f"/sessions/{_enc(session_id)}/evidence", idempotent=True)["data"]

    def verify_evidence_on_server(self, session_id: str) -> Dict[str, Any]:
        return self._c._request("GET", f"/sessions/{_enc(session_id)}/evidence/verify", idempotent=True)["data"]


class _Evidence:
    def __init__(self, client: "Biometrics") -> None:
        self._c = client

    def keys(self) -> List[Dict[str, Any]]:
        """The organization's Ed25519 public keys (including retired ones)."""
        return self._c._request("GET", "/evidence-keys", idempotent=True)["data"]

    def verify(self, session_id: str, keys: Optional[List[Mapping[str, Any]]] = None) -> Dict[str, Any]:
        """Verifies the evidence signature LOCALLY (Ed25519) with the public key."""
        s = self._c.sessions.get(session_id)
        ev = s.get("evidence") or {}
        sig = ev.get("signature")
        if not sig:
            raise BiometricsError("Session has no signed evidence", status=0, code="EVIDENCE_NOT_SIGNED")
        return verify_evidence_signature(s["sessionId"], s["attempt"], ev["bundleHash"], sig, keys if keys is not None else self.keys())


class Biometrics:
    """Catalisa Biometrics client.

    >>> bio = Biometrics(api_key="prefixo.segredo")
    >>> s = bio.sessions.create(flow="LIVENESS_ONLY", purpose="abertura de conta")
    >>> s["handoff"]["captureUrl"]
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        access_token: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        max_retries: int = 2,
        subaccount_id: Optional[str] = None,
        transport: Optional[Transport] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not api_key and not access_token:
            raise ValueError("Biometrics: api_key (or access_token) is required")
        self._api_key = api_key
        self._access_token = access_token
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._subaccount_id = subaccount_id
        self._transport = transport or urllib_transport
        self._sleep = sleep
        self.sessions = _Sessions(self)
        self.evidence = _Evidence(self)

    # -- core ----------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        query: Optional[Mapping[str, Any]] = None,
        idempotent: bool,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        url = self._base_url + path
        q = {k: str(v) for k, v in (query or {}).items() if v is not None and v != ""}
        if q:
            url += "?" + urllib.parse.urlencode(q)
        h = {"Accept": "application/json", "User-Agent": f"catalisa-biometrics-python/{VERSION}"}
        if headers:
            h.update(headers)
        if self._access_token:
            h["Authorization"] = f"Bearer {self._access_token}"
        elif self._api_key:
            h["X-API-Key"] = self._api_key
        if self._subaccount_id:
            h["X-Subaccount-Id"] = self._subaccount_id
        data = None
        if body is not None:
            h["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")

        attempt = 0
        while True:
            try:
                return self._once(method, url, h, data)
            except BiometricsError as err:
                retryable = isinstance(err, RateLimitError) or (
                    idempotent and (err.status >= 500 or isinstance(err, APIConnectionError))
                )
                if not retryable or attempt >= self._max_retries:
                    raise
                self._sleep(self._backoff(attempt, err))
                attempt += 1

    @staticmethod
    def _backoff(attempt: int, err: BiometricsError) -> float:
        if isinstance(err, RateLimitError) and err.retry_after is not None:
            return min(err.retry_after, 30.0)
        base = 0.5 * 2**attempt
        return min(base + random.random() * base * 0.25, 8.0)

    def _once(self, method: str, url: str, headers: Dict[str, str], data: Optional[bytes]) -> Any:
        try:
            res = self._transport(method, url, headers, data, self._timeout)
        except (socket.timeout, TimeoutError) as e:
            raise APIConnectionError(f"No response within {self._timeout} s", status=0, code="TIMEOUT") from e
        except (urllib.error.URLError, OSError) as e:
            reason = getattr(e, "reason", e)
            code = "TIMEOUT" if isinstance(reason, (socket.timeout, TimeoutError)) else "CONNECTION"
            raise APIConnectionError(f"Connection failed: {reason}", status=0, code=code) from e
        parsed: Any = None
        if res.body:
            try:
                parsed = json.loads(res.body)
            except ValueError:
                parsed = res.body.decode("utf-8", "replace")
        if res.status >= 400:
            raise error_from_response(res.status, parsed, res.headers)
        return parsed


def _enc(value: str) -> str:
    if not value:
        raise ValueError("Biometrics: empty id")
    return urllib.parse.quote(value, safe="")

