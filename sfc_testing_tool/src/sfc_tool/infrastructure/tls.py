"""Build a CA bundle from the Windows certificate store (standard library only).

Corporate CAs are usually installed in Windows but unknown to Python's bundled
certifi list, which causes 'unable to get local issuer certificate'.
"""
from __future__ import annotations

import ssl
from typing import Iterable

_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"


def windows_entries_to_pem(entries: Iterable[tuple]) -> str:
    """Convert ssl.enum_certificates() entries to a de-duplicated PEM bundle.

    Keeps DER certs trusted for server authentication (trust is True or a set of
    OIDs containing serverAuth). Pure function, so it can be tested anywhere.
    """
    seen, pems = set(), []
    for der, encoding, trust in entries:
        if encoding != "x509_asn":
            continue
        if trust is not True and _SERVER_AUTH not in (trust or ()):
            continue
        if der in seen:
            continue
        seen.add(der)
        pems.append(ssl.DER_cert_to_PEM_cert(der))
    return "".join(pems)


def export_windows_ca_bundle(path: str) -> int:
    """Write ROOT + intermediate (CA) stores to `path`. Windows only. Returns count."""
    if not hasattr(ssl, "enum_certificates"):
        raise OSError("ssl.enum_certificates is only available on Windows.")
    entries = []
    for store in ("ROOT", "CA"):
        entries.extend(ssl.enum_certificates(store))
    pem = windows_entries_to_pem(entries)
    with open(path, "w", encoding="ascii") as fh:
        fh.write(pem)
    return pem.count("BEGIN CERTIFICATE")
