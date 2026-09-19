"""Typed errors, with the same hierarchy as the Node SDK."""

from __future__ import annotations

from typing import Any, Mapping, Optional


class BiometricsError(Exception):
    """API error. ``code`` is ``details.code`` when the server sends one (QUOTA_EXCEEDED,
    SUBACCOUNT_SUSPENDED...) and ``error`` otherwise (VALIDATION, NOT_FOUND...)."""

    def __init__(
        self,
        message: str,
        *,
        status: int,
        code: str,
        request_id: Optional[str] = None,
        details: Any = None,
        body: Any = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.request_id = request_id
        self.details = details
        self.body = body

    def __repr__(self) -> str:  # pragma: no cover
        return f"{type(self).__name__}(status={self.status}, code={self.code!r}, message={self.message!r})"


class AuthenticationError(BiometricsError):
    """401 — missing, invalid, revoked or expired key."""


class PermissionDeniedError(BiometricsError):
    """403 without a subaccount sub-code (missing permission, subject locked)."""



class QuotaExceededError(BiometricsError):
    """402 QUOTA_EXCEEDED — the subaccount's monthly quota is used up."""


class SubaccountSuspendedError(BiometricsError):
    """403 SUBACCOUNT_SUSPENDED — the subaccount is suspended."""


class ValidationError(BiometricsError):
    """400 — invalid input."""


class NotFoundError(BiometricsError):
    """404."""


class RateLimitError(BiometricsError):
    """429. ``retry_after`` in seconds, when the server provides it."""

    def __init__(self, message: str, *, retry_after: Optional[float] = None, **kw: Any) -> None:
        super().__init__(message, **kw)
        self.retry_after = retry_after


class ServerError(BiometricsError):
    """5xx."""


class APIConnectionError(BiometricsError):
    """No response (network/timeout). ``code`` = TIMEOUT or CONNECTION."""



class WebhookVerificationError(BiometricsError):
    """Webhook delivery not authentic or outside the tolerance. ``code`` says why."""


def error_from_response(status: int, body: Any, headers: Mapping[str, str]) -> BiometricsError:
    b = body if isinstance(body, dict) else {}
    details = b.get("details")
    detail_code = details.get("code") if isinstance(details, dict) and isinstance(details.get("code"), str) else None
    top = b.get("error") if isinstance(b.get("error"), str) else None
    code = detail_code or top or f"HTTP_{status}"
    message = (
        (b.get("message") if isinstance(b.get("message"), str) and b.get("message") else None)
        or (b.get("error_description") if isinstance(b.get("error_description"), str) else None)
        or f"Biometrics API responded with HTTP {status}"
    )
    low = {k.lower(): v for k, v in headers.items()}
    kw: dict = dict(status=status, code=code, request_id=low.get("x-request-id") or low.get("x-trace-id"), details=details, body=body)
    if status == 402 or code == "QUOTA_EXCEEDED":
        return QuotaExceededError(message, **kw)
    if code == "SUBACCOUNT_SUSPENDED":
        return SubaccountSuspendedError(message, **kw)
    if status == 401:
        return AuthenticationError(message, **kw)
    if status == 403:
        return PermissionDeniedError(message, **kw)
    if status == 404:
        return NotFoundError(message, **kw)
    if status == 429:
        retry_after: Optional[float] = None
        try:
            retry_after = float(low["retry-after"])
        except (KeyError, ValueError):
            ra = b.get("retry_after")
            retry_after = float(ra) if isinstance(ra, (int, float)) else None
        return RateLimitError(message, retry_after=retry_after, **kw)
    if status >= 500:
        return ServerError(message, **kw)
    if status in (400, 413, 415, 422):
        return ValidationError(message, **kw)
    return BiometricsError(message, **kw)
