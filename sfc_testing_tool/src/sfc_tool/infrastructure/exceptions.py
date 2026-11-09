"""Exception hierarchy. Messages must never contain credentials or endpoints."""
from __future__ import annotations

from typing import Optional


class SfcToolError(Exception):
    """Base class for all application errors."""


class ConfigurationError(SfcToolError):
    pass


class EnvironmentGuardError(SfcToolError):
    """Raised when a request would leave the authorized QA environment."""


class EnvelopeBuildError(SfcToolError):
    """Invalid method/parameter name or value while building a SOAP request."""


class TransportError(SfcToolError):
    """Network-level failure (no usable HTTP response)."""


class ConnectFailedError(TransportError):
    """Could not establish a connection: the request never reached the server."""


class TlsVerificationError(TransportError):
    """TLS certificate could not be verified (usually a missing corporate CA)."""


class ReadTimeoutError(TransportError):
    """Request may have reached the server. Outcome UNKNOWN; never auto-retried."""


class HttpStatusError(TransportError):
    def __init__(self, status: int, message: str = "") -> None:
        super().__init__(message or "Unexpected HTTP status %s" % status)
        self.status = status


class ResponseParseError(SfcToolError):
    pass


class SoapFaultError(SfcToolError):
    def __init__(self, faultcode: str, faultstring: str,
                 http_status: Optional[int] = None) -> None:
        super().__init__("SOAP Fault: %s" % (faultstring or faultcode))
        self.faultcode = faultcode
        self.faultstring = faultstring
        self.http_status = http_status


class SessionError(SfcToolError):
    """Base class for session-lifecycle errors."""


class NotAuthenticatedError(SessionError):
    """A transaction was attempted without an authenticated session."""


class DeviceMismatchError(SessionError):
    """Transaction device differs from the device the session is logged in on."""


class InvalidStateError(SessionError):
    """Operation not allowed in the current session state."""
