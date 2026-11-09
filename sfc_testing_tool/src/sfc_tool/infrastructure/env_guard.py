"""Protection against accidental requests outside the authorized QA environment."""
from __future__ import annotations

from urllib.parse import urlparse

from .exceptions import EnvironmentGuardError
from .settings import Settings


def assert_qa_endpoint(settings: Settings) -> None:
    """Raise EnvironmentGuardError unless the endpoint is explicitly allowed QA.

    Rules (all must hold):
      1. settings.environment == "QA" (case-insensitive)
      2. scheme is http or https
      3. host is in the explicit allow-list (exact match, case-insensitive)
      4. URL contains none of the forbidden markers (default: "prod")
    Messages deliberately omit the URL/host.
    """
    if settings.environment.strip().upper() != "QA":
        raise EnvironmentGuardError("Environment is not QA; execution blocked.")
    parsed = urlparse(settings.endpoint_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise EnvironmentGuardError("Endpoint URL is not a valid http(s) URL.")
    allowed = {h.strip().lower() for h in settings.allowed_hosts if h.strip()}
    if not allowed:
        raise EnvironmentGuardError("Allow-list is empty; execution blocked.")
    if parsed.hostname.lower() not in allowed:
        raise EnvironmentGuardError("Endpoint host is not in the QA allow-list.")
    url_l = settings.endpoint_url.lower()
    for marker in settings.forbidden_markers:
        if marker and marker.lower() in url_l:
            raise EnvironmentGuardError("Endpoint matches a forbidden marker.")
