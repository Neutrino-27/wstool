"""Settings loading and validation. No credentials are ever stored here."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import List, Union

from .exceptions import ConfigurationError

ENV_VAR = "SFC_TOOL_CONFIG"
DEFAULT_PATH = os.path.join("config", "settings.json")

_REQUIRED = ("environment", "endpoint_url", "allowed_hosts", "xml_namespace",
             "soap_action_base")


@dataclass(frozen=True)
class Settings:
    environment: str
    endpoint_url: str
    allowed_hosts: List[str]
    xml_namespace: str
    soap_action_base: str
    host_header: str = ""
    forbidden_markers: List[str] = field(default_factory=lambda: ["prod"])
    connect_timeout_s: float = 5.0
    read_timeout_s: float = 15.0
    connect_retries: int = 1
    # True, False, or a path to a corporate CA bundle (only relevant for https)
    verify_tls: Union[bool, str] = True
    log_dir: str = "logs"
    log_level: str = "INFO"
    # WTSP_LOGINOUT `status` selectors. login=1 and device-check=5 are documented;
    # logout is configurable until confirmed against the real service.
    login_status: str = "1"
    logout_status: str = "2"
    device_check_status: str = "5"
    # Lower-case fragments of a p_ret=0 message meaning "session no longer valid".
    # Empty until a real example is captured; never guessed.
    session_invalid_markers: List[str] = field(default_factory=list)

    def __repr__(self) -> str:  # never leak endpoints through repr/logging
        return "Settings(environment=%r, ...)" % self.environment


def load_settings(path: str = "") -> Settings:
    path = path or os.environ.get(ENV_VAR, "") or DEFAULT_PATH
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        raise ConfigurationError(
            "Settings file not found. Copy config/settings.example.json to "
            "config/settings.json or set %s." % ENV_VAR)
    except (OSError, ValueError) as exc:
        raise ConfigurationError("Settings file unreadable or invalid JSON: %s"
                                 % type(exc).__name__)

    if not isinstance(raw, dict):
        raise ConfigurationError("Settings root must be a JSON object.")
    missing = [k for k in _REQUIRED if not raw.get(k)]
    if missing:
        raise ConfigurationError("Missing required settings: %s"
                                 % ", ".join(missing))
    if any("REPLACE-WITH" in str(raw.get(k, "")) for k in _REQUIRED):
        raise ConfigurationError("Settings still contain REPLACE-WITH placeholders.")
    unknown = set(raw) - set(Settings.__dataclass_fields__)
    if unknown:
        raise ConfigurationError("Unknown settings: %s" % ", ".join(sorted(unknown)))
    if not isinstance(raw["allowed_hosts"], list):
        raise ConfigurationError("allowed_hosts must be a list.")
    try:
        settings = Settings(**raw)
    except TypeError as exc:
        raise ConfigurationError("Invalid settings: %s" % exc)
    if isinstance(settings.verify_tls, str) and not os.path.isfile(settings.verify_tls):
        raise ConfigurationError(
            "verify_tls CA bundle file not found. Run scripts/export_windows_ca_bundle.py "
            "or correct the path.")
    return settings
