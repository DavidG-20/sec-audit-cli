"""Offline deterministic unit tests for sec-audit-cli."""

import json
from pathlib import Path

from sec_audit_cli.analyzer import (
    analyze_cookies,
    analyze_headers,
    analyze_tls,
    compute_score_and_grade,
)
from sec_audit_cli.models import AuditReport, TLSInfo
from sec_audit_cli.reporter import export_html, export_json, render_html


def test_hardened_https_site_receives_grade_a() -> None:
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=(), camera=()",
    }
    cookies = ["session=abc123; HttpOnly; Secure; SameSite=Strict"]
    tls = TLSInfo(
        protocol="TLSv1.3",
        issuer="organizationName=Let's Encrypt",
        subject="commonName=example.com",
        expires_at="2027-05-01",
        days_remaining=120,
        valid=True,
    )

    findings = [
        *analyze_headers(headers, is_https=True),
        *analyze_cookies(cookies, is_https=True),
        *analyze_tls(tls, is_https=True),
    ]
    score, grade = compute_score_and_grade(findings)
    assert score == 100
    assert grade == "A"


def test_insecure_http_site_fails_checks_and_gets_low_grade() -> None:
    headers = {"Server": "Apache/2.4.49", "X-Powered-By": "PHP/7.4.1"}
    cookies = ["sid=xyz"]

    findings = [
        *analyze_headers(headers, is_https=False),
        *analyze_cookies(cookies, is_https=False),
        *analyze_tls(None, is_https=False),
    ]
    score, grade = compute_score_and_grade(findings)
    assert score < 50
    assert grade == "F"
    assert any(f.status == "warn" and "Exposición" in f.check_name for f in findings)
    assert any(f.status == "fail" and "Cookies" in f.check_name for f in findings)


def test_tls_expiring_soon_triggers_warning() -> None:
    tls = TLSInfo(
        protocol="TLSv1.3",
        issuer="Test CA",
        subject="example.com",
        expires_at="2026-12-10",
        days_remaining=15,
        valid=True,
    )
    findings = analyze_tls(tls, is_https=True)
    assert len(findings) == 1
    assert findings[0].status == "warn"


def test_html_report_escapes_malicious_headers_and_json_exports(tmp_path: Path) -> None:
    malicious_headers = {"Referrer-Policy": "<script>alert('xss')</script>"}
    findings = analyze_headers(malicious_headers, is_https=False)
    score, grade = compute_score_and_grade(findings)
    report = AuditReport(
        target_url="http://localhost:8000",
        final_url="http://localhost:8000",
        status_code=200,
        score=score,
        grade=grade,
        findings=findings,
    )

    html_output = render_html(report)
    assert "<script>alert('xss')</script>" not in html_output
    assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_output

    html_file = tmp_path / "audit.html"
    json_file = tmp_path / "audit.json"
    export_html(report, html_file)
    export_json(report, json_file)

    assert html_file.exists()
    parsed = json.loads(json_file.read_text(encoding="utf-8"))
    assert parsed["grade"] == grade
    assert parsed["score"] == score


def test_obsolete_tls_protocol_fails_check() -> None:
    tls = TLSInfo(
        protocol="TLSv1.1",
        issuer="Test CA",
        subject="example.com",
        expires_at="2027-06-01",
        days_remaining=180,
        valid=True,
    )
    findings = analyze_tls(tls, is_https=True)
    assert findings[0].status == "fail"
    assert "obsoleto" in findings[0].detail.lower()
