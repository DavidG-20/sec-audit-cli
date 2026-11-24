# sec-audit-cli — Auditor de Seguridad Web (HTTP, Cookies y TLS/SSL)

Herramienta CLI defensiva de **AppSec / DevSecOps** en Python que audita cabeceras de seguridad HTTP, atributos de cookies y certificados TLS/SSL de cualquier aplicación web autorizada, calculando una **calificación A–F** con recomendaciones claras en español y exportación a **HTML / JSON**.

## Qué audita

1. **Cabeceras de seguridad (OWASP)**:
   - `Strict-Transport-Security` (HSTS en sitios HTTPS)
   - `Content-Security-Policy` (CSP y detección de `'unsafe-inline'`/`'unsafe-eval'`)
   - `X-Content-Type-Options` (`nosniff`)
   - Protección contra *Clickjacking* (`X-Frame-Options` o `frame-ancestors`)
   - `Referrer-Policy` y `Permissions-Policy`
   - Fuga de versiones en `Server` y `X-Powered-By`
2. **Seguridad de Cookies (`Set-Cookie`)**:
   - Verifica `HttpOnly`, `Secure` (en HTTPS) y `SameSite`.
3. **Certificados TLS/SSL**:
   - Inspecciona protocolo negociado (`TLSv1.3` / `TLSv1.2`), emisor, cadena válida y días restantes antes del vencimiento (alerta si faltan ≤ 30 días).
4. **Reportes seguros**:
   - Exporta a JSON (`--json-out`) y a HTML autocontenido (`--html-out`) escapando todos los valores remotos con `html.escape()` para prevenir XSS en el propio reporte.

## Arquitectura

```text
sec-audit-cli/
├── .agents/skills/appsec-auditor/   # Reglas de auditoría defensiva y escape HTML
├── AGENTS.md                        # Reglas del proyecto
├── src/sec_audit_cli/
│   ├── main.py                      # Interfaz CLI (Typer + Rich)
│   ├── models.py                    # Dataclasses tipados (SecurityFinding, TLSInfo, AuditReport)
│   ├── analyzer.py                  # Motor puro de reglas OWASP y puntuación A–F
│   ├── tls_checker.py               # Inspección TLS/SSL con ssl + socket
│   └── reporter.py                  # Exportadores JSON y HTML escapado
└── tests/
    └── test_auditor.py              # Pruebas offline deterministas (pytest)
```

## Instalación

```bash
git clone https://github.com/DavidG-20/sec-audit-cli.git
cd sec-audit-cli
uv sync
```

## Uso rápido

Auditar tu propia API local (por ejemplo `shorty-api` o `stockflow-pos`) o un sitio propio autorizado:

```bash
uv run secaudit http://localhost:8000
```

Exportar reportes en HTML y JSON:

```bash
uv run secaudit https://tu-sitio-autorizado.com --html-out reporte.html --json-out reporte.json
```

## Ejecutar pruebas

```bash
uv run pytest -v
```

## Aviso ético

Usa esta herramienta únicamente sobre aplicaciones, servidores o dominios propios o donde cuentes con autorización explícita.

## Licencia

MIT
