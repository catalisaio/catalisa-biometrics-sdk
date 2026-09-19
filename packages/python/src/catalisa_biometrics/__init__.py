"""Catalisa Biometrics — SDK Python (só stdlib).

O resultado de uma verificação vem pelo webhook ``biometrics.session.completed`` (verifique com
``verify_webhook``/``construct_event``) ou por ``Biometrics.sessions.get`` — nunca pela página de captura.
"""

from .client import DEFAULT_BASE_URL, STAGING_BASE_URL, VERSION, Biometrics, HttpResponse, urllib_transport
from .errors import (
    APIConnectionError,
    AuthenticationError,
    BiometricsError,
    NotFoundError,
    PermissionDeniedError,
    QuotaExceededError,
    RateLimitError,
    ServerError,
    SubaccountSuspendedError,
    ValidationError,
    WebhookVerificationError,
)
from .evidence import evidence_message, verify_evidence_signature
from .webhooks import check_webhook, construct_event, verify_webhook

__version__ = VERSION

__all__ = [
    "Biometrics",
    "DEFAULT_BASE_URL",
    "STAGING_BASE_URL",
    "HttpResponse",
    "urllib_transport",
    "verify_webhook",
    "construct_event",
    "check_webhook",
    "verify_evidence_signature",
    "evidence_message",
    "BiometricsError",
    "AuthenticationError",
    "PermissionDeniedError",
    "QuotaExceededError",
    "SubaccountSuspendedError",
    "ValidationError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
    "APIConnectionError",
    "WebhookVerificationError",
    "__version__",
]
