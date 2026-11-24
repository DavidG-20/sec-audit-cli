"""TLS/SSL certificate inspection using Python's standard ssl and socket modules."""

from datetime import datetime, timezone
import socket
import ssl
from urllib.parse import urlparse

from sec_audit_cli.models import TLSInfo


def _flatten_dn(dn_tuples: tuple) -> str:
    parts = []
    for rdn in dn_tuples:
        for key, value in rdn:
            if key in {"commonName", "organizationName"}:
                parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else "Desconocido"


def inspect_tls(url: str, timeout: float = 10.0) -> TLSInfo | None:
    """Inspect the TLS protocol and certificate of an HTTPS URL."""
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return None

    host = parsed.hostname
    port = parsed.port or 443
    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version() or "Desconocido"
    except (OSError, ssl.SSLError) as exc:
        return TLSInfo(
            protocol="N/A",
            issuer="N/A",
            subject="N/A",
            expires_at="N/A",
            days_remaining=0,
            valid=False,
            error=f"Error TLS/SSL: {exc}",
        )

    not_after_str = str(cert.get("notAfter", ""))
    try:
        expires_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        return TLSInfo(
            protocol=protocol,
            issuer="N/A",
            subject="N/A",
            expires_at="N/A",
            days_remaining=0,
            valid=False,
            error=f"Certificado sin fecha de expiración válida: {exc}",
        )
    days_remaining = (expires_dt - datetime.now(timezone.utc)).days

    return TLSInfo(
        protocol=protocol,
        issuer=_flatten_dn(cert.get("issuer", ())),
        subject=_flatten_dn(cert.get("subject", ())),
        expires_at=expires_dt.strftime("%Y-%m-%d"),
        days_remaining=days_remaining,
        valid=True,
    )
