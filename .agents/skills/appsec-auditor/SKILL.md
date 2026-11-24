---
name: appsec-auditor
description: Reglas de auditoría HTTP/TLS defensiva, escape de reportes y pruebas offline para sec-audit-cli.
---

# Reglas de Auditoría Defensiva (AppSec)

- Solo audita URLs con esquema `http` o `https` (rechaza otros esquemas).
- Usa siempre *timeouts* explícitos (`10s`) y límite de redirecciones (`5`) en `httpx`.
- En la inspección TLS/SSL usa `ssl.create_default_context()` para validar cadena de certificados y *hostname*.
- Escapa cualquier cabecera o valor remoto con `html.escape()` antes de escribirlo en reportes HTML.
- Separa estrictamente el motor de análisis (`analyzer.py`, `tls_checker.py`) de la capa de consola (`main.py`).
