# Reglas del proyecto `sec-audit-cli`

- Stack: **Python 3.12+**, **`uv`**, **Typer**, **Rich**, **httpx** y biblioteca estándar (`ssl`, `socket`, `html`).
- Código interno en **inglés técnico**; mensajes CLI, recomendaciones y `README.md` en **español**.
- Toda salida HTML debe escapar datos externos con `html.escape()` para evitar XSS en reportes generados.
- Las pruebas con `pytest` deben ser 100% deterministas y sin dependencias de internet en vivo.
