# SFC Testing Tool: Phase 2 core

Scope: integration + infrastructure layers only. The existing notebook is untouched and still works.

Setup:
1. `pip install requests defusedxml` (defusedxml optional)
2. Copy `config/settings.example.json` to `config/settings.json` and fill in QA values (never commit it).
3. Run tests: `set PYTHONPATH=src` then `python -m unittest discover -s tests -t . -v` (Windows cmd)

Layout: `infrastructure/` (settings, env guard, logging, exceptions), `integration/` (envelope builder, parser, SOAP client).
No credentials are stored in config; they will be held by the Phase 3 SessionManager and cleared at logout.

## Phase 3 additions
- `integration/response_classifier.py`: p_ret-based result classification (login, logout, status-5 check, transactions).
- `application/session_manager.py`: 5-state lifecycle, device gate, explicit "Login Twice" recovery, shutdown logout.
- New settings: `login_status`, `logout_status` (default "2", UNVERIFIED), `device_check_status`, `session_invalid_markers`.
- `scripts/manual_session_check.py`: manual login/logout check against QA (not part of automated tests).
