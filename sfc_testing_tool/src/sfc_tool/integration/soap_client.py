"""Centralized SOAP-over-HTTP client. The only module that touches the network."""
from __future__ import annotations

import logging
import time
from typing import Any, Optional

import requests

from ..infrastructure.env_guard import assert_qa_endpoint
from ..infrastructure.exceptions import (
    ConnectFailedError, HttpStatusError, ReadTimeoutError, ResponseParseError,
    SoapFaultError, TransportError)
from ..infrastructure.logging_setup import redact_params, redact_xml
from ..infrastructure.settings import Settings
from .envelope_builder import Params, build_envelope
from .models import SoapResponse
from .response_parser import extract_result, find_fault, parse_envelope

log = logging.getLogger("sfc_tool.soap")


def _failed_before_send(exc: requests.RequestException) -> bool:
    """True only when we are sure the request never reached the server."""
    if isinstance(exc, requests.ConnectTimeout):
        return True
    if isinstance(exc, requests.ConnectionError) and exc.args:
        try:
            from urllib3.exceptions import MaxRetryError, NewConnectionError
        except ImportError:  # pragma: no cover
            return False
        first = exc.args[0]
        return isinstance(first, MaxRetryError) and isinstance(first.reason, NewConnectionError)
    return False


class SoapClient:
    """Sends SOAP 1.1 calls to the QA web service.

    - requests.Session for keep-alive (and cookies, should the server set any).
    - The QA environment guard runs on construction and before every call.
    - Redirects are never followed (credentials must not be re-posted elsewhere).
    - Retries apply ONLY to failures proven to occur before the request was sent
      (connect timeout / connection refused). A read timeout is never retried:
      the server may already have processed a manufacturing transaction.
    """

    def __init__(self, settings: Settings,
                 session: Optional[requests.Session] = None) -> None:
        assert_qa_endpoint(settings)
        self._s = settings
        self._session = session or requests.Session()

    def close(self) -> None:
        self._session.close()

    def call(self, method: str, params: Params, *, isn: str = "") -> SoapResponse:
        assert_qa_endpoint(self._s)
        envelope = build_envelope(method, self._s.xml_namespace, params)
        headers = {"Content-Type": "text/xml; charset=utf-8",
                   # Same (unquoted) format as the original, verified working.
                   "SOAPAction": "%s%s" % (self._s.soap_action_base, method)}
        if self._s.host_header:
            headers["Host"] = self._s.host_header

        safe_params = redact_params(dict(params) if not hasattr(params, "items") else params)
        started = time.perf_counter()
        status: Optional[int] = None
        outcome = "ERROR"
        result_text = ""
        try:
            resp = self._post(envelope, headers)
            status = resp.status_code
            raw = resp.text if resp.encoding else resp.content.decode("utf-8", "replace")
            log.debug("soap_raw", extra={"fields": {
                "method": method, "request_xml": redact_xml(envelope),
                "response_xml": raw}})
            result_text = self._interpret(method, resp, raw)
            outcome = "TRANSPORT_OK"
            elapsed = int((time.perf_counter() - started) * 1000)
            return SoapResponse(method, status, result_text, elapsed, raw)
        except SoapFaultError:
            outcome = "SOAP_FAULT"
            raise
        except HttpStatusError:
            outcome = "HTTP_ERROR"
            raise
        except ResponseParseError:
            outcome = "PARSE_ERROR"
            raise
        except TransportError as exc:
            outcome = type(exc).__name__
            raise
        finally:
            log.info("soap_call", extra={"fields": {
                "operation": method, "isn": isn, "params": safe_params,
                "http_status": status, "duration_ms": int((time.perf_counter() - started) * 1000),
                "outcome": outcome, "server_result": result_text}})

    # -- internals -----------------------------------------------------------
    def _post(self, envelope: str, headers: dict) -> requests.Response:
        attempts = 1 + max(0, self._s.connect_retries)
        timeout = (self._s.connect_timeout_s, self._s.read_timeout_s)
        for attempt in range(1, attempts + 1):
            try:
                return self._session.post(
                    self._s.endpoint_url, data=envelope.encode("utf-8"),
                    headers=headers, timeout=timeout,
                    verify=self._s.verify_tls, allow_redirects=False)
            except requests.ReadTimeout:
                raise ReadTimeoutError(
                    "Read timeout: the server may have processed the request.")
            except requests.RequestException as exc:
                if _failed_before_send(exc):
                    if attempt < attempts:
                        log.warning("soap_connect_retry", extra={"fields": {"attempt": attempt}})
                        continue
                    raise ConnectFailedError("Could not connect to the web service.")
                raise TransportError("Network error: %s" % type(exc).__name__)
        raise ConnectFailedError("Could not connect to the web service.")  # pragma: no cover

    @staticmethod
    def _interpret(method: str, resp: requests.Response, raw: str) -> str:
        status = resp.status_code
        if 300 <= status < 400:
            raise HttpStatusError(status, "Unexpected redirect (not followed).")
        body_present = bool(resp.content and resp.content.strip())
        root = None
        if body_present:
            try:
                root = parse_envelope(resp.content)
            except ResponseParseError:
                if status >= 400:
                    raise HttpStatusError(status)
                raise
        fault = find_fault(root) if root is not None else None
        if fault is not None:
            fault.http_status = status
            raise fault
        if status >= 400 or root is None:
            raise HttpStatusError(status)
        return extract_result(root, method)
