import unittest

from sfc_tool.infrastructure.exceptions import ResponseParseError
from sfc_tool.integration.response_parser import (
    extract_result, find_fault, parse_envelope)
from .helpers import FAULT, soap_ok


class Parser(unittest.TestCase):
    def test_extract_result(self):
        self.assertEqual(extract_result(parse_envelope(soap_ok("WTSP_RESULT", "  1,OK  ")), "WTSP_RESULT"), "1,OK")

    def test_entity_encoded_content_decoded(self):
        r = extract_result(parse_envelope(soap_ok("M", "a &amp; b &lt;c&gt;")), "M")
        self.assertEqual(r, "a & b <c>")

    def test_self_closing_result_is_empty_string(self):
        xml = ('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
               '<MResponse><MResult /></MResponse></soap:Body></soap:Envelope>')
        self.assertEqual(extract_result(parse_envelope(xml), "M"), "")

    def test_prefixed_result_found(self):
        xml = ('<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:n="urn:x">'
               '<s:Body><n:MResponse><n:MResult>v</n:MResult></n:MResponse></s:Body></s:Envelope>')
        self.assertEqual(extract_result(parse_envelope(xml), "M"), "v")

    def test_fault_detected(self):
        f = find_fault(parse_envelope(FAULT))
        self.assertEqual((f.faultcode, f.faultstring), ("soap:Server", "Boom"))

    def test_no_fault_returns_none(self):
        self.assertIsNone(find_fault(parse_envelope(soap_ok("M", "x"))))

    def test_missing_result_raises(self):
        with self.assertRaises(ResponseParseError):
            extract_result(parse_envelope(soap_ok("M", "x")), "Other")

    def test_malformed_raises(self):
        with self.assertRaises(ResponseParseError):
            parse_envelope("<a><b></a>")

    def test_entity_bomb_rejected_when_defusedxml_present(self):
        try:
            import defusedxml  # noqa
        except ImportError:
            self.skipTest("defusedxml not installed")
        bomb = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]><x>&b;</x>'
        with self.assertRaises(ResponseParseError):
            parse_envelope(bomb)


if __name__ == "__main__":
    unittest.main()
