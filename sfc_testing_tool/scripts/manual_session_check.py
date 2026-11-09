r"""MANUAL check against the QA service: device check (status 5) -> login -> logout.

Sends ONLY login/logout traffic (no WTSP_RESULT). Run it yourself, never in CI:
    set PYTHONPATH=src
    python scripts\manual_session_check.py
It prints what the server answered so you can confirm the logout status value and
capture real status-5 / logout responses (remove names/IDs before sharing them).
"""
import getpass

from sfc_tool.application.session_manager import Credentials, SessionManager
from sfc_tool.infrastructure.logging_setup import setup_logging
from sfc_tool.infrastructure.settings import load_settings
from sfc_tool.integration.soap_client import SoapClient


class Echo:
    """Wraps the client to print the raw result text (this is YOUR screen only)."""
    def __init__(self, inner): self.inner = inner
    def call(self, method, params, isn=""):
        r = self.inner.call(method, params, isn=isn)
        print("   raw result text:", repr(r.result_text))
        return r


def main():
    s = load_settings()
    setup_logging(s.log_dir, s.log_level)
    print("Environment:", s.environment, "| logout status selector:", s.logout_status)
    c = Credentials(
        program_id=input("programId: "), program_password=getpass.getpass("programPassword: "),
        op=input("op: "), password=getpass.getpass("password: "),
        device=input("device: "), tsp=input("TSP [SFIS]: ") or "SFIS")
    m = SessionManager(Echo(SoapClient(s)), s)
    try:
        print("1) device check:", m.check_device(c).outcome.value)
        if input("Continue with login? (y/N) ").lower() != "y":
            return
        r = m.login(c); print("2) login:", r.outcome.value, "|", r.message)
        if r.outcome.value == "ALREADY_LOGGED_IN":
            print("Device already logged in; stopping (no automatic recovery in this script).")
            return
        if m.state.value == "AUTHENTICATED":
            r = m.logout(); print("3) logout:", r.outcome.value, "|", r.message)
    finally:
        m.shutdown()


if __name__ == "__main__":
    main()
