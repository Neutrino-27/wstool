import dataclasses
import logging
import os
import tempfile
import unittest

import requests
from urllib3.exceptions import MaxRetryError, NewConnectionError

from sfc_tool.infrastructure.exceptions import (
    ConnectFailedError, EnvironmentGuardError, HttpStatusError, ReadTimeoutError,
    ResponseParseError, SoapFaultError, TlsVerificationError, TransportError)
from sfc_tool.infrastructure.logging_setup import setup_logging
from sfc_tool.integration.soap_client import SoapClient
from .helpers import FAULT, NS, SETTINGS, FakeResponse, FakeSession, soap_ok

P = {"programId": "PID", "programPassword": "TOP-SECRET-PW", "ISN": "SN1"}


def refused():
    return requests.ConnectionError(MaxRetryError(None, "u", NewConnectionError(None, "refused")))


class Client(unittest.TestCase):
    def test_success_and_request_shape(self):
        s = FakeSession(FakeResponse(200, soap_ok("WTSP_RESULT", "ok")))
        r = SoapClient(SETTINGS, s).call("WTSP_RESULT", P, isn="SN1")
        self.assertEqual((r.result_text, r.http_status), ("ok", 200))
        url, kw = s.calls[0]
        self.assertEqual(url, SETTINGS.endpoint_url)
        self.assertEqual(kw["headers"]["SOAPAction"], NS + "WTSP_RESULT")
        self.assertEqual(kw["headers"]["Host"], "qa-host.invalid")
        self.assertEqual(kw["headers"]["Content-Type"], "text/xml; charset=utf-8")
        self.assertIs(kw["allow_redirects"], False)
        self.assertEqual(kw["timeout"], (5.0, 15.0))

    def test_guard_blocks_construction(self):
        with self.assertRaises(EnvironmentGuardError):
            SoapClient(dataclasses.replace(SETTINGS, environment="PROD"), FakeSession())

    def test_fault_on_http_500(self):
        s = FakeSession(FakeResponse(500, FAULT))
        with self.assertRaises(SoapFaultError) as cm:
            SoapClient(SETTINGS, s).call("M", P)
        self.assertEqual((cm.exception.faultstring, cm.exception.http_status), ("Boom", 500))

    def test_http_error_non_xml(self):
        with self.assertRaises(HttpStatusError) as cm:
            SoapClient(SETTINGS, FakeSession(FakeResponse(503, "<html>down"))).call("M", P)
        self.assertEqual(cm.exception.status, 503)

    def test_redirect_not_followed(self):
        with self.assertRaises(HttpStatusError):
            SoapClient(SETTINGS, FakeSession(FakeResponse(302, ""))).call("M", P)

    def test_200_with_garbage_is_parse_error(self):
        with self.assertRaises(ResponseParseError):
            SoapClient(SETTINGS, FakeSession(FakeResponse(200, "not xml"))).call("M", P)

    def test_200_empty_body(self):
        with self.assertRaises(HttpStatusError):
            SoapClient(SETTINGS, FakeSession(FakeResponse(200, ""))).call("M", P)

    def test_read_timeout_never_retried(self):
        s = FakeSession(requests.ReadTimeout(), FakeResponse(200, soap_ok("M", "x")))
        with self.assertRaises(ReadTimeoutError):
            SoapClient(SETTINGS, s).call("M", P)
        self.assertEqual(len(s.calls), 1)

    def test_connect_timeout_retried_once_then_succeeds(self):
        s = FakeSession(requests.ConnectTimeout(), FakeResponse(200, soap_ok("M", "x")))
        self.assertEqual(SoapClient(SETTINGS, s).call("M", P).result_text, "x")
        self.assertEqual(len(s.calls), 2)

    def test_connection_refused_retry_exhausted(self):
        s = FakeSession(refused(), refused())
        with self.assertRaises(ConnectFailedError):
            SoapClient(SETTINGS, s).call("M", P)
        self.assertEqual(len(s.calls), 2)

    def test_ambiguous_connection_error_not_retried(self):
        s = FakeSession(requests.ConnectionError("Connection aborted"), FakeResponse(200, soap_ok("M", "x")))
        with self.assertRaises(TransportError) as cm:
            SoapClient(SETTINGS, s).call("M", P)
        self.assertNotIsInstance(cm.exception, ConnectFailedError)
        self.assertEqual(len(s.calls), 1)

    def test_tls_failure_is_actionable_not_retried_and_hides_host(self):
        s = FakeSession(requests.exceptions.SSLError("CERTIFICATE_VERIFY_FAILED host=qa-host.invalid"),
                        FakeResponse(200, soap_ok("M", "x")))
        with self.assertRaises(TlsVerificationError) as cm:
            SoapClient(SETTINGS, s).call("M", P)
        self.assertEqual(len(s.calls), 1)
        self.assertIn("verify_tls", str(cm.exception))
        self.assertNotIn("qa-host", str(cm.exception))
        self.assertIsNone(cm.exception.__cause__)
        self.assertTrue(cm.exception.__suppress_context__)

    def test_secret_never_reaches_log_file(self):
        d = tempfile.mkdtemp()
        logger = setup_logging(d, "DEBUG")
        self.addCleanup(lambda: [logger.removeHandler(h) or h.close() for h in list(logger.handlers) if getattr(h, '_sfc_handler', False)])
        s = FakeSession(FakeResponse(200, soap_ok("WTSP_RESULT", "1,OK")))
        SoapClient(SETTINGS, s).call("WTSP_RESULT", P, isn="SN1")
        for h in logger.handlers: h.flush()
        with open(os.path.join(d, "sfc_tool.log"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("TOP-SECRET-PW", text)
        self.assertIn("SN1", text)
        self.assertIn("duration_ms", text)
        self.assertIn("request_xml", text)   # DEBUG detail present, but redacted


if __name__ == "__main__":
    unittest.main()
