import unittest

from sfc_tool.integration.response_classifier import (
    Outcome, classify_device_check, classify_login, classify_logout,
    classify_transaction, split_result)
from sfc_tool.integration.response_parser import extract_result, parse_envelope
from tests.fixtures import sanitized_responses as F
from .helpers import soap_ok


class Classifier(unittest.TestCase):
    def test_split(self):
        self.assertEqual(split_result("1abc"), (1, "abc"))
        self.assertEqual(split_result("0 x"), (0, "x"))
        self.assertEqual(split_result("garbage"), (None, "garbage"))
        self.assertEqual(split_result(""), (None, ""))

    def test_login(self):
        self.assertEqual(classify_login(F.LOGIN_OK).outcome, Outcome.LOGIN_OK)
        self.assertTrue(classify_login(F.LOGIN_OK).ok)
        for text, outcome in ((F.LOGIN_TWICE, Outcome.ALREADY_LOGGED_IN),
                              (F.LOGIN_USER_NOT_FOUND, Outcome.USER_NOT_FOUND),
                              (F.LOGIN_DEVICE_UNDEFINED, Outcome.DEVICE_NOT_DEFINED),
                              ("0something new", Outcome.LOGIN_FAILED)):
            r = classify_login(text)
            self.assertEqual(r.outcome, outcome); self.assertFalse(r.ok)

    def test_login_case_insensitive_and_unknown(self):
        self.assertEqual(classify_login("0LOGIN TWICE!").outcome, Outcome.ALREADY_LOGGED_IN)
        r = classify_login("<html>error</html>")
        self.assertEqual(r.outcome, Outcome.UNKNOWN); self.assertFalse(r.ok)

    def test_old_substring_bugs_cannot_happen(self):
        # Previously "OK"/"PASS" substrings made these look like success.
        for text in ("0NOT OK", "0PASSWORD INVALID", "0TOKEN EXPIRED"):
            self.assertFalse(classify_login(text).ok)
            self.assertFalse(classify_transaction(text).ok)

    def test_logout(self):
        self.assertTrue(classify_logout(F.LOGOUT_OK).ok)
        self.assertEqual(classify_logout("0nope").outcome, Outcome.LOGOUT_FAILED)
        self.assertEqual(classify_logout("???").outcome, Outcome.UNKNOWN)

    def test_device_check_distinguishes_same_ret(self):
        free, used = classify_device_check(F.CHECK_FREE), classify_device_check(F.CHECK_IN_USE)
        self.assertEqual((free.ret, used.ret), (1, 1))
        self.assertEqual(free.outcome, Outcome.DEVICE_FREE)
        self.assertEqual(used.outcome, Outcome.DEVICE_IN_USE)
        self.assertEqual(used.detail, {"operator": "P1234", "since": "2006/01/01 08:00:05"})
        self.assertEqual(classify_device_check("1weird").outcome, Outcome.UNKNOWN)
        self.assertEqual(classify_device_check(F.LOGIN_DEVICE_UNDEFINED).outcome, Outcome.DEVICE_NOT_DEFINED)

    def test_transaction(self):
        self.assertEqual(classify_transaction(F.RESULT_OK).outcome, Outcome.ACCEPTED)
        self.assertEqual(classify_transaction(F.RESULT_BAD_ISN).outcome, Outcome.REJECTED_ISN)
        self.assertEqual(classify_transaction(F.RESULT_WRONG_STEP).outcome, Outcome.REJECTED_ROUTE)
        self.assertEqual(classify_transaction("0other").outcome, Outcome.REJECTED)

    def test_session_invalid_only_when_configured(self):
        self.assertEqual(classify_transaction("0PLEASE LOGIN FIRST").outcome, Outcome.REJECTED)
        r = classify_transaction("0PLEASE LOGIN FIRST", ["login first"])
        self.assertEqual(r.outcome, Outcome.SESSION_INVALID)

    def test_end_to_end_from_soap_xml(self):
        xml = soap_ok("WTSP_RESULT", F.RESULT_BAD_ISN)
        text = extract_result(parse_envelope(xml), "WTSP_RESULT")
        self.assertEqual(classify_transaction(text).outcome, Outcome.REJECTED_ISN)


if __name__ == "__main__":
    unittest.main()
