"""SOAP 1.1 request builder.

Produces the same envelope structure as the original tool (soap:Envelope with
xsi/xsd/soap prefixes, method element in the service default namespace, child
parameters in the caller's order), but every value is escaped and every name
validated. Built as text on purpose: xml.etree would emit ns0:-style prefixes,
which are semantically equivalent but differ from the verified structure.
Tests parse the output with ElementTree to prove it is well-formed.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Tuple, Union
from xml.sax.saxutils import escape

from ..infrastructure.exceptions import EnvelopeBuildError

# W3C / SOAP 1.1 standard namespaces (public constants, not corporate data).
XMLNS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
XMLNS_XSD = "http://www.w3.org/2001/XMLSchema"
XMLNS_SOAP = "http://schemas.xmlsoap.org/soap/envelope/"

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Characters illegal in XML 1.0
_ILLEGAL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")
_ENTITIES = {'"': "&quot;", "'": "&apos;"}

Params = Union[Mapping[str, Any], Iterable[Tuple[str, Any]]]


def _check_name(kind: str, name: str) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise EnvelopeBuildError("Invalid %s name." % kind)
    return name


def _encode_value(name: str, value: Any) -> str:
    text = "" if value is None else str(value)
    if _ILLEGAL_RE.search(text):
        raise EnvelopeBuildError("Parameter '%s' contains characters not allowed in XML." % name)
    return escape(text, _ENTITIES)


def build_envelope(method: str, namespace: str, params: Params) -> str:
    """Build a SOAP 1.1 envelope. Parameter order is preserved as given."""
    _check_name("method", method)
    items = params.items() if isinstance(params, Mapping) else params
    body = "".join(
        "<{n}>{v}</{n}>".format(n=_check_name("parameter", k), v=_encode_value(k, v))
        for k, v in items)
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:xsi="{xsi}" xmlns:xsd="{xsd}" xmlns:soap="{soap}">'
        '<soap:Body><{m} xmlns="{ns}">{body}</{m}></soap:Body>'
        "</soap:Envelope>"
    ).format(xsi=XMLNS_XSI, xsd=XMLNS_XSD, soap=XMLNS_SOAP,
             m=method, ns=escape(namespace, {'"': "&quot;"}), body=body)
