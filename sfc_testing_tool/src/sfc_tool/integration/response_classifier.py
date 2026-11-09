"""Interpret the text inside <...Result> returned by the SFIS web service.

Observed wire format (from captured responses): the first character is p_ret
('1' = OK, '0' = failure) immediately followed by p_msg, with no delimiter, and
sometimes an echoed trailer (e.g. the device number). p_ret is the ONLY success
signal. Message text is used solely to *categorize* failures, and for the
status=5 device check where both outcomes return p_ret=1.
Anything unrecognized becomes Outcome.UNKNOWN and is never treated as success.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional


class Outcome(str, Enum):
    LOGIN_OK = "LOGIN_OK"
    ALREADY_LOGGED_IN = "ALREADY_LOGGED_IN"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    DEVICE_NOT_DEFINED = "DEVICE_NOT_DEFINED"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT_OK = "LOGOUT_OK"
    LOGOUT_FAILED = "LOGOUT_FAILED"
    DEVICE_FREE = "DEVICE_FREE"
    DEVICE_IN_USE = "DEVICE_IN_USE"
    CHECK_FAILED = "CHECK_FAILED"
    ACCEPTED = "ACCEPTED"
    REJECTED_ISN = "REJECTED_ISN"
    REJECTED_ROUTE = "REJECTED_ROUTE"
    REJECTED = "REJECTED"
    SESSION_INVALID = "SESSION_INVALID"
    UNKNOWN = "UNKNOWN"


_SUCCESS = {Outcome.LOGIN_OK, Outcome.LOGOUT_OK, Outcome.DEVICE_FREE,
            Outcome.DEVICE_IN_USE, Outcome.ACCEPTED}


@dataclass(frozen=True)
class Classified:
    outcome: Outcome
    ret: Optional[int]
    message: str
    detail: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.outcome in _SUCCESS


def split_result(text: str) -> tuple[Optional[int], str]:
    t = (text or "").strip()
    if t[:1] in ("0", "1"):
        return int(t[0]), t[1:].strip()
    return None, t


def _has(low: str, *frags: str) -> bool:
    return any(f in low for f in frags)


def classify_login(text: str) -> Classified:
    ret, msg = split_result(text)
    low = msg.lower()
    if ret is None:
        return Classified(Outcome.UNKNOWN, ret, msg)
    if ret == 1:
        return Classified(Outcome.LOGIN_OK, ret, msg)
    if _has(low, "login twice"):
        o = Outcome.ALREADY_LOGGED_IN
    elif _has(low, "user not found"):
        o = Outcome.USER_NOT_FOUND
    elif _has(low, "device not defined"):
        o = Outcome.DEVICE_NOT_DEFINED
    else:
        o = Outcome.LOGIN_FAILED
    return Classified(o, ret, msg)


def classify_logout(text: str) -> Classified:
    ret, msg = split_result(text)
    if ret is None:
        return Classified(Outcome.UNKNOWN, ret, msg)
    return Classified(Outcome.LOGOUT_OK if ret == 1 else Outcome.LOGOUT_FAILED, ret, msg)


def classify_device_check(text: str) -> Classified:
    """status=5: p_ret=1 for BOTH 'in use' and 'not been used'; read the message."""
    ret, msg = split_result(text)
    low = msg.lower()
    if ret is None:
        return Classified(Outcome.UNKNOWN, ret, msg)
    if ret == 0:
        o = Outcome.DEVICE_NOT_DEFINED if _has(low, "device not defined") else Outcome.CHECK_FAILED
        return Classified(o, ret, msg)
    if "not been used" in low:          # test first: it is the unambiguous one
        return Classified(Outcome.DEVICE_FREE, ret, msg)
    if "in used" in low:
        detail = {}
        for key, pat in (("operator", r"OP:\[(.*?)\]"), ("since", r"ON:\[(.*?)\]")):
            m = re.search(pat, msg, re.IGNORECASE)
            if m:
                detail[key] = m.group(1)
        return Classified(Outcome.DEVICE_IN_USE, ret, msg, detail)
    return Classified(Outcome.UNKNOWN, ret, msg)


def classify_transaction(text: str, session_invalid_markers: Iterable[str] = ()) -> Classified:
    ret, msg = split_result(text)
    low = msg.lower()
    if ret is None:
        return Classified(Outcome.UNKNOWN, ret, msg)
    if ret == 1:
        return Classified(Outcome.ACCEPTED, ret, msg)
    if any(m and m.lower() in low for m in session_invalid_markers):
        return Classified(Outcome.SESSION_INVALID, ret, msg)
    if _has(low, "wrong isn", "(chk_isn)"):
        o = Outcome.REJECTED_ISN
    elif _has(low, "wrong step", "route error"):
        o = Outcome.REJECTED_ROUTE
    else:
        o = Outcome.REJECTED
    return Classified(o, ret, msg)
