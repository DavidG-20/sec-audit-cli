"""Safe JSON and HTML report exporters (with strict HTML escaping)."""

from dataclasses import asdict
import html
import json
from pathlib import Path

from sec_audit_cli.models import AuditReport


def export_json(report: AuditReport, output_path: Path) -> None:
    """Write the AuditReport as formatted UTF-8 JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(asdict(report), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def render_html(report: AuditReport) -> str:
    """Render a self-contained, XSS-safe HTML security audit report."""
    rows = []
    for f in report.findings:
        badge_class = {"pass": "ok", "warn": "warn", "fail": "fail"}.get(f.status, "warn")
        rows.append(
            f"<tr>"
            f"<td><span class='badge {badge_class}'>{html.escape(f.status.upper())}</span></td>"
            f"<td>{html.escape(f.category)}</td>"
            f"<td><strong>{html.escape(f.check_name)}</strong></td>"
            f"<td>{html.escape(f.detail)}</td>"
            f"<td>{html.escape(f.recommendation)}</td>"
            f"</tr>"
        )

    tls_block = ""
    if report.tls:
        tls_block = (
            f"<p class='meta'><strong>TLS:</strong> {html.escape(report.tls.protocol)} | "
            f"<strong>Emisor:</strong> {html.escape(report.tls.issuer)} | "
            f"<strong>Vence:</strong> {html.escape(report.tls.expires_at)} "
            f"({report.tls.days_remaining} días)</p>"
        )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <title>Reporte de Auditoría — {html.escape(report.target_url)}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background:#0f172a; color:#f1f5f9; margin:2rem; }}
    .card {{ background:#1e293b; border:1px solid #334155; border-radius:12px; padding:1.5rem; max-width:1100px; margin:auto; }}
    .meta {{ color:#94a3b8; font-size:0.95rem; }}
    .grade {{ font-size:2rem; font-weight:800; color:#38bdf8; }}
    table {{ width:100%; border-collapse:collapse; margin-top:1rem; font-size:0.9rem; }}
    th, td {{ text-align:left; padding:0.65rem; border-bottom:1px solid #334155; }}
    th {{ color:#94a3b8; }}
    .badge {{ padding:0.2rem 0.55rem; border-radius:999px; font-size:0.75rem; font-weight:700; }}
    .ok {{ background:rgba(34,197,94,0.2); color:#4ade80; }}
    .warn {{ background:rgba(245,158,11,0.2); color:#fbbf24; }}
    .fail {{ background:rgba(239,68,68,0.2); color:#f87171; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Reporte de Auditoría de Seguridad Web</h1>
    <p class="meta"><strong>Objetivo:</strong> {html.escape(report.final_url)} | <strong>HTTP:</strong> {report.status_code}</p>
    {tls_block}
    <p class="grade">Calificación: {html.escape(report.grade)} ({report.score}/100)</p>
    <table>
      <thead>
        <tr><th>Estado</th><th>Categoría</th><th>Verificación</th><th>Detalle</th><th>Recomendación</th></tr>
      </thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
</body>
</html>
"""


def export_html(report: AuditReport, output_path: Path) -> None:
    """Write the escaped HTML audit report to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html(report), encoding="utf-8")
