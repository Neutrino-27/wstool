from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SoapResponse:
    """Transport-level result of a successful SOAP call.

    result_text is the *unclassified* content of <{method}Result>. Interpreting
    it (p_ret / p_msg) is the job of the ResponseClassifier (Phase 3/4), which
    will be built from captured real responses.
    """
    method: str
    http_status: int
    result_text: str
    elapsed_ms: int
    raw_xml: str
