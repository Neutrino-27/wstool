import unittest
from xml.etree import ElementTree as ET

from sfc_tool.infrastructure.exceptions import EnvelopeBuildError
from sfc_tool.integration.envelope_builder import (
    XMLNS_SOAP, XMLNS_XSD, XMLNS_XSI, build_envelope)
from .helpers import NS


def legacy_login(v):
    """Reference: the ORIGINAL f-string builder (cell 3) with placeholder values."""
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="{XMLNS_XSI}" xmlns:xsd="{XMLNS_XSD}" xmlns:soap="{XMLNS_SOAP}">
<soap:Body>
<WTSP_LOGINOUT xmlns="{NS}">
<programId>{v['programId']}</programId>
<programPassword>{v['programPassword']}</programPassword>
<op>{v['op']}</op>
<password>{v['password']}</password>
<device>{v['device']}</device>
<TSP>{v['TSP']}</TSP>
<status>{v['status']}</status>
</WTSP_LOGINOUT>
</soap:Body>
</soap:Envelope>"""


def legacy_result(v):
    keys = ["programId", "programPassword", "ISN", "error", "device", "TSP", "data", "status", "CPKFlag"]
    els = "".join(f"<{k}>{v.get(k, '')}</{k}>" for k in keys)
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="{XMLNS_XSI}" xmlns:xsd="{XMLNS_XSD}" xmlns:soap="{XMLNS_SOAP}">
<soap:Body><WTSP_RESULT xmlns="{NS}">{els}</WTSP_RESULT></soap:Body>
</soap:Envelope>"""


def canon(xml):
    """Structure-only fingerprint: (tag, text, children), ignoring whitespace."""
    def walk(e):
        return (e.tag, (e.text or "").strip(), [walk(c) for c in e])
    return walk(ET.fromstring(xml.encode("utf-8")))


LOGIN = {"programId": "PID", "programPassword": "PPW", "op": "OP1",
         "password": "PW", "device": "310010", "TSP": "SFIS", "status": "1"}
RESULT = {"programId": "PID", "programPassword": "PPW", "ISN": "SN001", "error": "0",
          "device": "310010", "TSP": "SFIS", "data": "TEST", "status": "8", "CPKFlag": ""}


class EnvelopeCompatibility(unittest.TestCase):
    def test_login_matches_legacy_structure(self):
        self.assertEqual(canon(build_envelope("WTSP_LOGINOUT", NS, LOGIN)), canon(legacy_login(LOGIN)))

    def test_result_matches_legacy_structure(self):
        self.assertEqual(canon(build_envelope("WTSP_RESULT", NS, RESULT)), canon(legacy_result(RESULT)))

    def test_default_namespace_on_method_element(self):
        root = ET.fromstring(build_envelope("WTSP_RESULT", NS, RESULT).encode())
        body = root[0]
        self.assertEqual(body[0].tag, "{%s}WTSP_RESULT" % NS)
        self.assertEqual(body[0][0].tag, "{%s}programId" % NS)

    def test_parameter_order_preserved(self):
        root = ET.fromstring(build_envelope("M", NS, [("b", "1"), ("a", "2")]).encode())
        self.assertEqual([c.tag.split("}")[1] for c in root[0][0]], ["b", "a"])


class EnvelopeSafety(unittest.TestCase):
    def test_all_fields_escaped_not_only_data(self):
        evil = {"programPassword": "p&ss<w>\"'", "ISN": "A&B"}
        root = ET.fromstring(build_envelope("M", NS, evil).encode())
        vals = {c.tag.split("}")[1]: c.text for c in root[0][0]}
        self.assertEqual(vals, evil)  # round-trips exactly

    def test_markup_injection_stays_text(self):
        root = ET.fromstring(build_envelope("M", NS, {"ISN": "</ISN><x>1</x>"}).encode())
        self.assertEqual(len(root[0][0]), 1)
        self.assertEqual(root[0][0][0].text, "</ISN><x>1</x>")

    def test_invalid_names_rejected(self):
        for bad in ("a b", "x><y", "1abc", "", "a/b"):
            with self.assertRaises(EnvelopeBuildError):
                build_envelope("M", NS, {bad: "v"})
            with self.assertRaises(EnvelopeBuildError):
                build_envelope(bad, NS, {})

    def test_control_characters_rejected(self):
        with self.assertRaises(EnvelopeBuildError):
            build_envelope("M", NS, {"data": "bad\x00char"})

    def test_none_becomes_empty(self):
        root = ET.fromstring(build_envelope("M", NS, {"a": None}).encode())
        self.assertEqual(root[0][0][0].text, None)

    def test_unicode_ok(self):
        root = ET.fromstring(build_envelope("M", NS, {"data": "Juárez ñ 測試"}).encode("utf-8"))
        self.assertEqual(root[0][0][0].text, "Juárez ñ 測試")


if __name__ == "__main__":
    unittest.main()
