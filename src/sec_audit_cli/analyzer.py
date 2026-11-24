"""Pure security analysis engine for HTTP headers, cookies, TLS info, and grading."""

from collections.abc import Mapping, Sequence

from sec_audit_cli.models import SecurityFinding, TLSInfo


def analyze_headers(headers: Mapping[str, str], is_https: bool) -> list[SecurityFinding]:
    """Evaluate response headers against OWASP security best practices."""
    norm = {k.lower(): v for k, v in headers.items()}
    findings: list[SecurityFinding] = []

    # 1. HSTS (only applicable on HTTPS)
    if is_https:
        hsts = norm.get("strict-transport-security", "")
        if "max-age=" in hsts.lower():
            findings.append(
                SecurityFinding(
                    category="headers",
                    check_name="Strict-Transport-Security (HSTS)",
                    status="pass",
                    weight=15,
                    detail=f"Presente: {hsts}",
                    recommendation="Mantén max-age >= 31536000 e incluye includeSubDomains.",
                )
            )
        else:
            findings.append(
                SecurityFinding(
                    category="headers",
                    check_name="Strict-Transport-Security (HSTS)",
                    status="fail",
                    weight=15,
                    detail="Falta cabecera HSTS en sitio HTTPS.",
                    recommendation="Agrega 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                )
            )

    # 2. Content-Security-Policy
    csp = norm.get("content-security-policy", "")
    if csp:
        unsafe = "'unsafe-inline'" in csp or "'unsafe-eval'" in csp
        findings.append(
            SecurityFinding(
                category="headers",
                check_name="Content-Security-Policy (CSP)",
                status="warn" if unsafe else "pass",
                weight=20,
                detail="Presente con directivas permisivas ('unsafe-inline'/'unsafe-eval')."
                if unsafe
                else "Política CSP configurada correctamente.",
                recommendation="Evita 'unsafe-inline' y restringe fuentes permitidas por origen."
                if unsafe
                else "Mantén la política CSP actualizada al añadir nuevos recursos.",
            )
        )
    else:
        findings.append(
            SecurityFinding(
                category="headers",
                check_name="Content-Security-Policy (CSP)",
                status="fail",
                weight=20,
                detail="Cabecera CSP ausente (mayor exposición a XSS).",
                recommendation="Define al menos \"Content-Security-Policy: default-src 'self'\".",
            )
        )

    # 3. X-Content-Type-Options
    xcto = norm.get("x-content-type-options", "").lower()
    findings.append(
        SecurityFinding(
            category="headers",
            check_name="X-Content-Type-Options",
            status="pass" if xcto == "nosniff" else "fail",
            weight=10,
            detail="Configurado como 'nosniff'." if xcto == "nosniff" else "Ausente o distinto de 'nosniff'.",
            recommendation="Configura 'X-Content-Type-Options: nosniff' para evitar MIME sniffing.",
        )
    )

    # 4. Clickjacking protection (X-Frame-Options or CSP frame-ancestors)
    xfo = norm.get("x-frame-options", "").upper()
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    clickjack_ok = xfo in {"DENY", "SAMEORIGIN"} or has_frame_ancestors
    findings.append(
        SecurityFinding(
            category="headers",
            check_name="Protección Clickjacking (X-Frame-Options)",
            status="pass" if clickjack_ok else "fail",
            weight=10,
            detail=f"Protegido ({xfo or 'CSP frame-ancestors'})." if clickjack_ok else "Sin protección contra Clickjacking.",
            recommendation="Agrega 'X-Frame-Options: DENY' o 'frame-ancestors' en CSP.",
        )
    )

    # 5. Referrer-Policy
    ref_pol = norm.get("referrer-policy", "")
    findings.append(
        SecurityFinding(
            category="headers",
            check_name="Referrer-Policy",
            status="pass" if ref_pol else "warn",
            weight=10,
            detail=f"Presente: {ref_pol}" if ref_pol else "Cabecera Referrer-Policy ausente.",
            recommendation="Usa 'Referrer-Policy: no-referrer' o 'strict-origin-when-cross-origin'.",
        )
    )

    # 6. Permissions-Policy
    perm_pol = norm.get("permissions-policy", "")
    findings.append(
        SecurityFinding(
            category="headers",
            check_name="Permissions-Policy",
            status="pass" if perm_pol else "warn",
            weight=5,
            detail="Política de permisos configurada." if perm_pol else "Cabecera Permissions-Policy ausente.",
            recommendation="Restringe APIs del navegador no usadas (cámara, micrófono, geolocalización).",
        )
    )

    # 7. Server / X-Powered-By version leak
    leaked = [
        f"{hdr}={norm[hdr]}"
        for hdr in ("server", "x-powered-by")
        if hdr in norm and any(ch.isdigit() for ch in norm[hdr])
    ]
    findings.append(
        SecurityFinding(
            category="headers",
            check_name="Exposición de versiones (Server / X-Powered-By)",
            status="warn" if leaked else "pass",
            weight=10,
            detail=f"Se exponen versiones: {', '.join(leaked)}" if leaked else "No se exponen versiones exactas de servidor.",
            recommendation="Oculta números de versión en cabeceras Server y X-Powered-By.",
        )
    )

    return findings


def analyze_cookies(set_cookie_headers: Sequence[str], is_https: bool) -> list[SecurityFinding]:
    """Check Set-Cookie headers for HttpOnly, Secure, and SameSite flags."""
    if not set_cookie_headers:
        return [
            SecurityFinding(
                category="cookies",
                check_name="Seguridad de Cookies",
                status="pass",
                weight=10,
                detail="El endpoint no establece cookies.",
                recommendation="Si agregas cookies de sesión, activa HttpOnly, Secure y SameSite.",
            )
        ]

    issues: list[str] = []
    for raw_cookie in set_cookie_headers:
        parts = [part.strip() for part in raw_cookie.split(";")]
        name = parts[0].split("=", 1)[0] if parts else "cookie"
        attrs = {part.lower().split("=", 1)[0] for part in parts[1:]}
        missing = []
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if is_https and "secure" not in attrs:
            missing.append("Secure")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if missing:
            issues.append(f"{name} (falta {', '.join(missing)})")

    if issues:
        return [
            SecurityFinding(
                category="cookies",
                check_name="Seguridad de Cookies",
                status="fail",
                weight=10,
                detail="Cookies inseguras: " + "; ".join(issues),
                recommendation="Activa HttpOnly, Secure (en HTTPS) y SameSite=Lax/Strict en todas las cookies.",
            )
        ]

    return [
        SecurityFinding(
            category="cookies",
            check_name="Seguridad de Cookies",
            status="pass",
            weight=10,
            detail=f"{len(set_cookie_headers)} cookie(s) con flags de seguridad completos.",
            recommendation="Mantén HttpOnly, Secure y SameSite en todas las cookies.",
        )
    ]


def analyze_tls(tls_info: TLSInfo | None, is_https: bool) -> list[SecurityFinding]:
    """Evaluate TLS protocol version and certificate validity."""
    if not is_https:
        return [
            SecurityFinding(
                category="tls",
                check_name="Cifrado en tránsito (HTTPS / TLS)",
                status="fail",
                weight=15,
                detail="El objetivo usa HTTP sin cifrado.",
                recommendation="Habilita HTTPS con certificado TLS válido (ej. Let's Encrypt) y redirige HTTP → HTTPS.",
            )
        ]

    if tls_info is None or not tls_info.valid:
        return [
            SecurityFinding(
                category="tls",
                check_name="Certificado TLS / SSL",
                status="fail",
                weight=15,
                detail=tls_info.error if tls_info and tls_info.error else "No se pudo validar el certificado TLS.",
                recommendation="Instala un certificado firmado por una CA confiable y revisa la cadena intermedia.",
            )
        ]

    if tls_info.protocol in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
        status_val, detail = "fail", f"Protocolo TLS obsoleto e inseguro ({tls_info.protocol})."
    elif tls_info.days_remaining <= 0:
        status_val, detail = "fail", f"Certificado vencido ({tls_info.expires_at})."
    elif tls_info.days_remaining <= 30:
        status_val, detail = "warn", f"Vence pronto ({tls_info.days_remaining} días, {tls_info.expires_at})."
    else:
        status_val, detail = "pass", f"{tls_info.protocol} válido ({tls_info.days_remaining} días restantes)."

    return [
        SecurityFinding(
            category="tls",
            check_name="Certificado TLS / SSL",
            status=status_val,
            weight=15,
            detail=detail,
            recommendation="Renueva certificados automáticamente antes de los 30 días previos al vencimiento.",
        )
    ]


def compute_score_and_grade(findings: Sequence[SecurityFinding]) -> tuple[int, str]:
    """Compute a 0–100 security score and letter grade (A–F)."""
    total_weight = sum(f.weight for f in findings)
    if total_weight == 0:
        return 100, "A"

    earned = 0.0
    for finding in findings:
        if finding.status == "pass":
            earned += finding.weight
        elif finding.status == "warn":
            earned += finding.weight * 0.5

    score = round((earned / total_weight) * 100)
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 65:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"
    return score, grade
