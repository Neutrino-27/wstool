import os
import tempfile
import unittest

from sfc_tool.application.session_manager import Credentials, SessionManager, SessionState as S
from sfc_tool.infrastructure.exceptions import (
    DeviceMismatchError, InvalidStateError, NotAuthenticatedError, ReadTimeoutError, SessionError)
from sfc_tool.infrastructure.logging_setup import setup_logging
from sfc_tool.integration.models import SoapResponse
from sfc_tool.integration.response_classifier import Outcome
from tests.fixtures import sanitized_responses as F
from .helpers import SETTINGS

import dataclasses
ST = dataclasses.replace(SETTINGS, session_invalid_markers=["login first"])


class FakeClient:
    def __init__(self, *script):
        self.script, self.calls = list(script), []

    def call(self, method, params, isn=""):
        self.calls.append((method, list(params), isn))
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return SoapResponse(method, 200, item, 1, "")

    def statuses(self):
        return [dict(p).get("status") for _, p, _ in self.calls]


def creds(device="310010"):
    return Credentials("PID", "SECRET-PROG-PW", "OP1", "SECRET-USER-PW", device)


def manager(*script):
    c = FakeClient(*script)
    return SessionManager(c, ST), c


class Login(unittest.TestCase):
    def test_success(self):
        m, c = manager(F.LOGIN_OK)
        r = m.login(creds())
        self.assertEqual((r.outcome, m.state, m.device), (Outcome.LOGIN_OK, S.AUTHENTICATED, "310010"))
        method, params, _ = c.calls[0]
        self.assertEqual(method, "WTSP_LOGINOUT")
        self.assertEqual([k for k, _ in params],
                         ["programId", "programPassword", "op", "password", "device", "TSP", "status"])
        self.assertEqual(dict(params)["status"], "1")

    def test_failure_clears_credentials(self):
        m, _ = manager(F.LOGIN_USER_NOT_FOUND)
        r = m.login(creds())
        self.assertEqual((r.outcome, m.state, m.device, m.has_pending_conflict),
                         (Outcome.USER_NOT_FOUND, S.DISCONNECTED, None, False))

    def test_transport_error_resets_state(self):
        m, _ = manager(ReadTimeoutError("x"))
        with self.assertRaises(ReadTimeoutError):
            m.login(creds())
        self.assertEqual(m.state, S.DISCONNECTED)

    def test_cannot_login_twice_locally(self):
        m, _ = manager(F.LOGIN_OK)
        m.login(creds())
        with self.assertRaises(InvalidStateError):
            m.login(creds())

    def test_credentials_repr_hides_secrets(self):
        self.assertNotIn("SECRET", repr(creds()))


class Conflict(unittest.TestCase):
    def test_login_twice_surfaced_not_auto_resolved(self):
        m, c = manager(F.LOGIN_TWICE)
        r = m.login(creds())
        self.assertEqual((r.outcome, m.state, m.has_pending_conflict), (Outcome.ALREADY_LOGGED_IN, S.DISCONNECTED, True))
        self.assertEqual(len(c.calls), 1)               # nothing automatic

    def test_recovery_requires_confirmation(self):
        m, c = manager(F.LOGIN_TWICE)
        m.login(creds())
        with self.assertRaises(SessionError):
            m.recover_already_logged_in(confirmed=False)
        self.assertEqual(len(c.calls), 1)

    def test_recovery_logs_out_then_in(self):
        m, c = manager(F.LOGIN_TWICE, F.LOGOUT_OK, F.LOGIN_OK)
        m.login(creds())
        r = m.recover_already_logged_in(confirmed=True)
        self.assertEqual((r.outcome, m.state, m.has_pending_conflict), (Outcome.LOGIN_OK, S.AUTHENTICATED, False))
        self.assertEqual(c.statuses(), ["1", "2", "1"])

    def test_recovery_stops_if_logout_fails(self):
        m, c = manager(F.LOGIN_TWICE, "0cannot")
        m.login(creds())
        r = m.recover_already_logged_in(confirmed=True)
        self.assertEqual((r.outcome, m.state, m.has_pending_conflict), (Outcome.LOGOUT_FAILED, S.DISCONNECTED, True))
        self.assertEqual(len(c.calls), 2)

    def test_cancel_pending(self):
        m, _ = manager(F.LOGIN_TWICE)
        m.login(creds()); m.cancel_pending()
        self.assertFalse(m.has_pending_conflict)
        with self.assertRaises(InvalidStateError):
            m.recover_already_logged_in(confirmed=True)


class Logout(unittest.TestCase):
    def test_logout_clears(self):
        m, c = manager(F.LOGIN_OK, F.LOGOUT_OK)
        m.login(creds()); r = m.logout()
        self.assertEqual((r.outcome, m.state, m.device), (Outcome.LOGOUT_OK, S.DISCONNECTED, None))
        self.assertEqual(c.statuses(), ["1", "2"])

    def test_failed_logout_keeps_session(self):
        m, _ = manager(F.LOGIN_OK, "0nope")
        m.login(creds()); r = m.logout()
        self.assertEqual((r.outcome, m.state, m.device), (Outcome.LOGOUT_FAILED, S.AUTHENTICATED, "310010"))

    def test_transport_error_in_logout_keeps_session(self):
        m, _ = manager(F.LOGIN_OK, ReadTimeoutError("x"))
        m.login(creds())
        with self.assertRaises(ReadTimeoutError):
            m.logout()
        self.assertEqual(m.state, S.AUTHENTICATED)

    def test_logout_when_disconnected_rejected(self):
        m, _ = manager()
        with self.assertRaises(InvalidStateError):
            m.logout()

    def test_shutdown_logs_out_and_wipes(self):
        m, c = manager(F.LOGIN_OK, F.LOGOUT_OK)
        m.login(creds()); m.shutdown()
        self.assertEqual((m.state, m.device, c.statuses()), (S.DISCONNECTED, None, ["1", "2"]))

    def test_shutdown_wipes_even_if_logout_errors(self):
        m, _ = manager(F.LOGIN_OK, ReadTimeoutError("x"))
        m.login(creds()); m.shutdown()
        self.assertEqual((m.state, m.device), (S.DISCONNECTED, None))


class DeviceCheck(unittest.TestCase):
    def test_pre_login_check_keeps_state(self):
        m, c = manager(F.CHECK_IN_USE)
        r = m.check_device(creds())
        self.assertEqual((r.outcome, m.state, c.statuses()), (Outcome.DEVICE_IN_USE, S.DISCONNECTED, ["5"]))
        self.assertEqual(r.detail["operator"], "P1234")

    def test_check_without_credentials_rejected(self):
        m, _ = manager()
        with self.assertRaises(InvalidStateError):
            m.check_device()


class Execute(unittest.TestCase):
    P = [("ISN", "SN1"), ("error", "0"), ("device", "310010"), ("TSP", "SFIS"),
         ("data", "TEST"), ("status", "8"), ("CPKFlag", "")]

    def test_blocked_when_not_authenticated(self):
        m, c = manager()
        with self.assertRaises(NotAuthenticatedError):
            m.execute("WTSP_RESULT", self.P)
        self.assertEqual(c.calls, [])

    def test_device_mismatch_blocked(self):
        m, c = manager(F.LOGIN_OK)
        m.login(creds())
        bad = [(k, "999999" if k == "device" else v) for k, v in self.P]
        with self.assertRaises(DeviceMismatchError):
            m.execute("WTSP_RESULT", bad)
        self.assertEqual(len(c.calls), 1)

    def test_injects_credentials_first_and_ignores_caller_overrides(self):
        m, c = manager(F.LOGIN_OK, F.RESULT_OK)
        m.login(creds())
        r = m.execute("WTSP_RESULT", [("programPassword", "EVIL")] + self.P, isn="SN1")
        self.assertEqual(r.outcome, Outcome.ACCEPTED)
        _, params, isn = c.calls[1]
        self.assertEqual(params[:2], [("programId", "PID"), ("programPassword", "SECRET-PROG-PW")])
        self.assertEqual([k for k, _ in params[2:]], [k for k, _ in self.P])
        self.assertEqual(isn, "SN1")

    def test_rejection_keeps_session(self):
        m, _ = manager(F.LOGIN_OK, F.RESULT_WRONG_STEP)
        m.login(creds())
        self.assertEqual(m.execute("WTSP_RESULT", self.P).outcome, Outcome.REJECTED_ROUTE)
        self.assertEqual(m.state, S.AUTHENTICATED)

    def test_session_invalid_marks_expired_then_blocks(self):
        m, c = manager(F.LOGIN_OK, "0PLEASE LOGIN FIRST", F.LOGOUT_OK)
        m.login(creds())
        self.assertEqual(m.execute("WTSP_RESULT", self.P).outcome, Outcome.SESSION_INVALID)
        self.assertEqual(m.state, S.SESSION_EXPIRED)
        with self.assertRaises(NotAuthenticatedError):
            m.execute("WTSP_RESULT", self.P)
        m.logout()                                   # explicit cleanup still possible
        self.assertEqual(m.state, S.DISCONNECTED)

    def test_read_timeout_propagates_state_unchanged(self):
        m, _ = manager(F.LOGIN_OK, ReadTimeoutError("x"))
        m.login(creds())
        with self.assertRaises(ReadTimeoutError):
            m.execute("WTSP_RESULT", self.P)
        self.assertEqual(m.state, S.AUTHENTICATED)


class Observability(unittest.TestCase):
    def test_listener_sees_transitions(self):
        m, _ = manager(F.LOGIN_OK, F.LOGOUT_OK)
        seen = []
        m.add_listener(lambda o, n: seen.append((o.value, n.value)))
        m.login(creds()); m.logout()
        self.assertEqual(seen, [("DISCONNECTED", "AUTHENTICATING"), ("AUTHENTICATING", "AUTHENTICATED"),
                                ("AUTHENTICATED", "LOGGING_OUT"), ("LOGGING_OUT", "DISCONNECTED")])

    def test_failing_listener_does_not_break_session(self):
        m, _ = manager(F.LOGIN_OK)
        m.add_listener(lambda o, n: 1 / 0)
        m.login(creds())
        self.assertEqual(m.state, S.AUTHENTICATED)

    def test_no_secrets_in_session_logs(self):
        d = tempfile.mkdtemp()
        logger = setup_logging(d, "DEBUG")
        self.addCleanup(lambda: [logger.removeHandler(h) or h.close() for h in list(logger.handlers) if getattr(h, '_sfc_handler', False)])
        m, _ = manager(F.LOGIN_OK, F.RESULT_OK, F.LOGOUT_OK)
        m.login(creds()); m.execute("WTSP_RESULT", Execute.P); m.logout()
        for h in logger.handlers: h.flush()
        with open(os.path.join(d, "sfc_tool.log"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("SECRET", text)
        self.assertIn("session_state", text)


if __name__ == "__main__":
    unittest.main()
