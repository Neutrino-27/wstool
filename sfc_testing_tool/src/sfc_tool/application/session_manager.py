"""Session lifecycle for the SFIS web service.

The server tracks login state per DEVICE and it outlives this process, so local
state is only a belief. Rules enforced here:
  * transactions only in AUTHENTICATED, and only for the logged-in device;
  * credentials are held only while needed and dropped on logout/failure;
  * "Login Twice" is surfaced, never auto-resolved: recovery needs explicit
    confirmation because it ends a session that may belong to someone else.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Optional

from ..infrastructure.exceptions import (
    DeviceMismatchError, InvalidStateError, NotAuthenticatedError, SessionError,
    SfcToolError)
from ..infrastructure.settings import Settings
from ..integration.models import SoapResponse
from ..integration.response_classifier import (
    Classified, Outcome, classify_device_check, classify_login, classify_logout,
    classify_transaction)

log = logging.getLogger("sfc_tool.session")
LOGIN_METHOD = "WTSP_LOGINOUT"


class SessionState(str, Enum):
    DISCONNECTED = "DISCONNECTED"
    AUTHENTICATING = "AUTHENTICATING"
    AUTHENTICATED = "AUTHENTICATED"
    LOGGING_OUT = "LOGGING_OUT"
    SESSION_EXPIRED = "SESSION_EXPIRED"


@dataclass(repr=False)
class Credentials:
    program_id: str
    program_password: str
    op: str
    password: str
    device: str
    tsp: str = "SFIS"

    def __repr__(self) -> str:  # secrets must never reach logs/tracebacks
        return "Credentials(device=%r, ...)" % self.device


class SessionManager:
    def __init__(self, client: Any, settings: Settings) -> None:
        self._client = client          # anything with .call(method, params, isn=...)
        self._s = settings
        self._lock = threading.RLock()
        self._state = SessionState.DISCONNECTED
        self._creds: Optional[Credentials] = None
        self._pending: Optional[Credentials] = None   # held after "Login Twice"
        self._listeners: list[Callable[[SessionState, SessionState], None]] = []

    # -- observation ---------------------------------------------------------
    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def device(self) -> Optional[str]:
        return self._creds.device if self._creds else None

    @property
    def has_pending_conflict(self) -> bool:
        return self._pending is not None

    def add_listener(self, fn: Callable[[SessionState, SessionState], None]) -> None:
        """fn(old, new) runs in the calling (worker) thread: GUIs must marshal."""
        self._listeners.append(fn)

    def _set(self, new: SessionState) -> None:
        old, self._state = self._state, new
        if old != new:
            log.info("session_state", extra={"fields": {
                "from": old.value, "to": new.value, "device": self.device}})
            for fn in list(self._listeners):
                try:
                    fn(old, new)
                except Exception:
                    log.exception("session_listener_failed")

    # -- protocol helpers ----------------------------------------------------
    @staticmethod
    def _login_params(c: Credentials, status: str) -> list[tuple[str, str]]:
        # Same order as the original working implementation.
        return [("programId", c.program_id), ("programPassword", c.program_password),
                ("op", c.op), ("password", c.password), ("device", c.device),
                ("TSP", c.tsp), ("status", status)]

    def _call_loginout(self, c: Credentials, status: str) -> SoapResponse:
        return self._client.call(LOGIN_METHOD, self._login_params(c, status), isn="")

    # -- lifecycle -----------------------------------------------------------
    def check_device(self, creds: Optional[Credentials] = None) -> Classified:
        """status=5: is anyone logged in on this device? Does not change state."""
        with self._lock:
            if self._state not in (SessionState.DISCONNECTED, SessionState.AUTHENTICATED):
                raise InvalidStateError("Device check not allowed in state %s." % self._state.value)
            c = creds or self._creds
            if c is None:
                raise InvalidStateError("Credentials required for a device check.")
            res = classify_device_check(
                self._call_loginout(c, self._s.device_check_status).result_text)
            log.info("device_check", extra={"fields": {"device": c.device, "outcome": res.outcome.value}})
            return res

    def login(self, creds: Credentials) -> Classified:
        with self._lock:
            if self._state != SessionState.DISCONNECTED:
                raise InvalidStateError("Login not allowed in state %s." % self._state.value)
            self._pending = None
            self._set(SessionState.AUTHENTICATING)
            try:
                resp = self._call_loginout(creds, self._s.login_status)
            except BaseException:
                self._set(SessionState.DISCONNECTED)
                raise
            res = classify_login(resp.result_text)
            if res.outcome == Outcome.LOGIN_OK:
                self._creds = creds
                self._set(SessionState.AUTHENTICATED)
            else:
                if res.outcome == Outcome.ALREADY_LOGGED_IN:
                    self._pending = creds      # kept ONLY to allow explicit recovery
                self._set(SessionState.DISCONNECTED)
            log.info("login", extra={"fields": {"device": creds.device, "outcome": res.outcome.value}})
            return res

    def logout(self) -> Classified:
        with self._lock:
            if self._state not in (SessionState.AUTHENTICATED, SessionState.SESSION_EXPIRED):
                raise InvalidStateError("Logout not allowed in state %s." % self._state.value)
            previous = self._state
            assert self._creds is not None
            self._set(SessionState.LOGGING_OUT)
            try:
                resp = self._call_loginout(self._creds, self._s.logout_status)
            except BaseException:
                self._set(previous)            # outcome unknown: stay recoverable
                raise
            res = classify_logout(resp.result_text)
            log.info("logout", extra={"fields": {"device": self.device, "outcome": res.outcome.value}})
            if res.outcome == Outcome.LOGOUT_OK:
                self._creds = None
                self._set(SessionState.DISCONNECTED)
            else:
                self._set(previous)
            return res

    def recover_already_logged_in(self, *, confirmed: bool) -> Classified:
        """After ALREADY_LOGGED_IN: log the device out, then log in again.

        Requires explicit confirmation: it ends a session that may belong to
        another operator. Returns the login result, or the failed logout result.
        """
        with self._lock:
            if not confirmed:
                raise SessionError("Explicit user confirmation is required.")
            if self._pending is None or self._state != SessionState.DISCONNECTED:
                raise InvalidStateError("No pending 'Login Twice' conflict to recover.")
            creds = self._pending
            out = classify_logout(self._call_loginout(creds, self._s.logout_status).result_text)
            log.info("conflict_logout", extra={"fields": {"device": creds.device, "outcome": out.outcome.value}})
            if out.outcome != Outcome.LOGOUT_OK:
                return out                     # still pending; user may retry/cancel
            return self.login(creds)

    def cancel_pending(self) -> None:
        with self._lock:
            self._pending = None

    def mark_expired(self, reason: str = "") -> None:
        with self._lock:
            if self._state == SessionState.AUTHENTICATED:
                log.warning("session_expired", extra={"fields": {"reason": reason, "device": self.device}})
                self._set(SessionState.SESSION_EXPIRED)

    def discard_local_session(self) -> None:
        """Drop local state/credentials WITHOUT server confirmation."""
        with self._lock:
            self._creds = None
            self._pending = None
            self._set(SessionState.DISCONNECTED)

    def shutdown(self) -> Optional[Classified]:
        """Best-effort logout on app exit, then always wipe local state."""
        result = None
        try:
            if self._state in (SessionState.AUTHENTICATED, SessionState.SESSION_EXPIRED):
                result = self.logout()
        except SfcToolError:
            log.warning("shutdown_logout_failed")
        finally:
            self.discard_local_session()
        return result

    # -- gated transaction execution ----------------------------------------
    def execute(self, method: str, params: Mapping[str, Any] | Iterable[tuple[str, Any]],
                *, isn: str = "") -> Classified:
        """Send one transaction. Phase 4 adds validation and batching on top."""
        with self._lock:
            if self._state != SessionState.AUTHENTICATED or self._creds is None:
                raise NotAuthenticatedError(
                    "Not authenticated (state %s)." % self._state.value)
            c = self._creds
        given = dict(params)
        if "device" in given and str(given["device"]) != c.device:
            raise DeviceMismatchError(
                "Transaction device differs from the logged-in device; log in on it first.")
        ordered = [("programId", c.program_id), ("programPassword", c.program_password)]
        ordered += [(k, v) for k, v in given.items() if k not in ("programId", "programPassword")]
        resp = self._client.call(method, ordered, isn=isn)
        res = classify_transaction(resp.result_text, self._s.session_invalid_markers)
        if res.outcome == Outcome.SESSION_INVALID:
            self.mark_expired(res.message)
        return res
