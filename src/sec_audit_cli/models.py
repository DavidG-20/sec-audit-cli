"""Typed data models for security findings, TLS info, and audit reports."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecurityFinding:
    """Single security check outcome."""

    category: str  # headers | cookies | tls
    check_name: str
    status: str  # pass | warn | fail
    weight: int
    detail: str
    recommendation: str


@dataclass(frozen=True)
class TLSInfo:
    """Summary of an inspected TLS/SSL certificate."""

    protocol: str
    issuer: str
    subject: str
    expires_at: str
    days_remaining: int
    valid: bool
    error: str | None = None


@dataclass
class AuditReport:
    """Complete security audit result for a target URL."""

    target_url: str
    final_url: str
    status_code: int
    score: int
    grade: str
    tls: TLSInfo | None = None
    findings: list[SecurityFinding] = field(default_factory=list)
