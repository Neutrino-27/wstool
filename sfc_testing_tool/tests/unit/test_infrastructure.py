import dataclasses
import json
import logging
import os
import tempfile
import unittest

from sfc_tool.infrastructure.env_guard import assert_qa_endpoint
from sfc_tool.infrastructure.exceptions import ConfigurationError, EnvironmentGuardError
from sfc_tool.infrastructure.logging_setup import (
    REDACTED, JsonFormatter, RedactingFilter, redact_params, redact_xml)
from sfc_tool.infrastructure.settings import load_settings
from .helpers import SETTINGS

EXAMPLE = os.path.join(os.path.dirname(__file__), "..", "..", "config", "settings.example.json")


class Guard(unittest.TestCase):
    def test_qa_allowed(self):
        assert_qa_endpoint(SETTINGS)

    def _blocked(self, **kw):
        with self.assertRaises(EnvironmentGuardError):
            assert_qa_endpoint(dataclasses.replace(SETTINGS, **kw))

    def test_wrong_environment(self): self._blocked(environment="PROD")
    def test_host_not_allowed(self): self._blocked(allowed_hosts=["other.invalid"])
    def test_empty_allow_list(self): self._blocked(allowed_hosts=[])
    def test_bad_scheme(self): self._blocked(endpoint_url="ftp://qa-host.invalid/x")
    def test_forbidden_marker(self):
        self._blocked(endpoint_url="http://qa-host.invalid/prod/svc.asmx")
    def test_lookalike_host_blocked(self):
        self._blocked(endpoint_url="http://qa-host.invalid.evil.example/svc")

    def test_message_does_not_leak_host(self):
        try:
            assert_qa_endpoint(dataclasses.replace(SETTINGS, allowed_hosts=["x.invalid"]))
        except EnvironmentGuardError as e:
            self.assertNotIn("qa-host", str(e))


class Settings(unittest.TestCase):
    def _write(self, data):
        fd, path = tempfile.mkstemp(suffix=".json"); os.close(fd)
        with open(path, "w") as f: json.dump(data, f)
        self.addCleanup(os.remove, path)
        return path

    def test_example_with_placeholders_rejected(self):
        with self.assertRaises(ConfigurationError):
            load_settings(EXAMPLE)

    def test_valid(self):
        s = load_settings(self._write({
            "environment": "QA", "endpoint_url": "http://h.invalid/s", "allowed_hosts": ["h.invalid"],
            "xml_namespace": "n", "soap_action_base": "n"}))
        self.assertEqual(s.read_timeout_s, 15.0)

    def test_missing_and_unknown(self):
        with self.assertRaises(ConfigurationError): load_settings(self._write({"environment": "QA"}))
        with self.assertRaises(ConfigurationError):
            load_settings(self._write({"environment": "QA", "endpoint_url": "u", "allowed_hosts": ["h"],
                                       "xml_namespace": "n", "soap_action_base": "n", "bogus": 1}))

    def test_missing_file(self):
        with self.assertRaises(ConfigurationError): load_settings("nope.json")

    def test_verify_tls_path_must_exist(self):
        base = {"environment": "QA", "endpoint_url": "https://h.invalid/s", "allowed_hosts": ["h.invalid"],
                "xml_namespace": "n", "soap_action_base": "n"}
        with self.assertRaises(ConfigurationError):
            load_settings(self._write(dict(base, verify_tls="no/such/ca.pem")))
        pem = self._write({})   # any existing file
        self.assertEqual(load_settings(self._write(dict(base, verify_tls=pem))).verify_tls, pem)

    def test_repr_hides_endpoint(self):
        self.assertNotIn("qa-host", repr(SETTINGS))


class Redaction(unittest.TestCase):
    def test_params(self):
        r = redact_params({"programPassword": "a", "password": "b", "ISN": "c", "Password": "d"})
        self.assertEqual(r, {"programPassword": REDACTED, "password": REDACTED, "ISN": "c", "Password": REDACTED})

    def test_xml(self):
        x = "<a><programPassword>secret</programPassword><password>s3</password><ISN>1</ISN></a>"
        out = redact_xml(x)
        self.assertNotIn("secret", out); self.assertNotIn("s3", out); self.assertIn("<ISN>1</ISN>", out)

    def test_filter_and_formatter(self):
        rec = logging.LogRecord("sfc_tool", logging.INFO, "", 0, "evt", None, None)
        rec.fields = {"password": "x", "request_xml": "<password>y</password>", "n": 1}
        RedactingFilter().filter(rec)
        line = JsonFormatter().format(rec)
        self.assertNotIn('"x"', line); self.assertNotIn(">y<", line)
        self.assertEqual(json.loads(line)["n"], 1)


if __name__ == "__main__":
    unittest.main()


class Tls(unittest.TestCase):
    def test_pem_bundle_filtering_and_dedupe(self):
        import certifi, ssl
        from sfc_tool.infrastructure.tls import windows_entries_to_pem
        with open(certifi.where(), encoding="ascii") as fh:
            first = fh.read().split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
        der = ssl.PEM_cert_to_DER_cert(first[first.index("-----BEGIN"):])
        entries = [(der, "x509_asn", True), (der, "x509_asn", {"1.3.6.1.5.5.7.3.1"}),   # duplicate
                   (der + b"x", "x509_asn", {"1.3.6.1.5.5.7.3.4"}),                      # wrong purpose
                   (der + b"y", "pkcs_7_asn", True)]                                      # wrong encoding
        out = windows_entries_to_pem(entries)
        self.assertEqual(out.count("BEGIN CERTIFICATE"), 1)
