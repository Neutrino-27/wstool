"""Namespace-aware SOAP response parsing (no regular expressions)."""
from __future__ import annotations

from typing import Optional, Union
from xml.etree import ElementTree as ET

try:  # optional hardening against entity-expansion attacks
    from defusedxml import ElementTree as _SafeET
    _fromstring = _SafeET.fromstring
except ImportError:  # pragma: no cover
    _fromstring = ET.fromstring

from ..infrastructure.exceptions import ResponseParseError, SoapFaultError


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _text(elem: ET.Element) -> str:
    return "".join(elem.itertext()).strip()


def parse_envelope(content: Union[bytes, str]) -> ET.Element:
    try:
        return _fromstring(content)
    except Exception as exc:  # ParseError, or defusedxml security errors
        raise ResponseParseError("Response is not well-formed XML (%s)."
                                 % type(exc).__name__)


def find_fault(root: ET.Element) -> Optional[SoapFaultError]:
    for elem in root.iter():
        if _local(elem.tag) == "Fault":
            code = string = ""
            for child in elem:
                name = _local(child.tag)
                if name == "faultcode":
                    code = _text(child)
                elif name == "faultstring":
                    string = _text(child)
            return SoapFaultError(code, string)
    return None


def extract_result(root: ET.Element, method: str) -> str:
    """Return the text of <{method}Result>, raising if it is absent."""
    target = method + "Result"
    for elem in root.iter():
        if _local(elem.tag) == target:
            return _text(elem)
    raise ResponseParseError("Response has no %s element." % target)
