"""CLI entry point for sec-audit-cli (Typer + Rich presentation layer)."""

from pathlib import Path
from urllib.parse import urlparse

import httpx
from rich.console import Console
from rich.table import Table
import typer

from sec_audit_cli.analyzer import (
    analyze_cookies,
    analyze_headers,
    analyze_tls,
    compute_score_and_grade,
)
from sec_audit_cli.models import AuditReport
from sec_audit_cli.reporter import export_html, export_json
from sec_audit_cli.tls_checker import inspect_tls

app = typer.Typer(
    name="secaudit",
    help="Auditor defensivo de seguridad web: cabeceras HTTP, cookies y certificados TLS/SSL.",
    no_args_is_help=True,
)
console = Console()


def _validate_url(raw_url: str) -> str:
    parsed = urlparse(raw_url.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise typer.BadParameter(
            "La URL debe incluir esquema http:// o https:// y un host válido."
        )
    return raw_url.strip()


def _render_report(report: AuditReport) -> None:
    grade_color = {"A": "green", "B": "cyan", "C": "yellow", "D": "dark_orange", "F": "red"}.get(
        report.grade, "white"
    )
    console.print(
        f"\nObjetivo: [bold]{report.final_url}[/bold] (HTTP {report.status_code})\n"
        f"Calificación: [bold {grade_color}]{report.grade} ({report.score}/100)[/bold {grade_color}]"
    )
    if report.tls:
        console.print(
            f"TLS: [bold]{report.tls.protocol}[/bold] | "
            f"Emisor: {report.tls.issuer} | "
            f"Vence: {report.tls.expires_at} ({report.tls.days_remaining} días)"
        )

    table = Table(title="Resultados de la auditoría", show_lines=False)
    table.add_column("Estado", style="bold")
    table.add_column("Categoría", style="cyan")
    table.add_column("Verificación", style="bold")
    table.add_column("Detalle")
    table.add_column("Recomendación", style="dim")

    status_styles = {"pass": "green", "warn": "yellow", "fail": "red"}
    for f in report.findings:
        color = status_styles.get(f.status, "white")
        table.add_row(
            f"[{color}]{f.status.upper()}[/{color}]",
            f.category,
            f.check_name,
            f.detail,
            f.recommendation,
        )
    console.print(table)


@app.command("scan")
def scan_url(
    url: str = typer.Argument(..., help="URL autorizada a auditar (ej. http://localhost:8000 o https://tu-sitio.com)."),
    timeout: float = typer.Option(10.0, "--timeout", help="Tiempo máximo de espera en segundos."),
    json_out: Path | None = typer.Option(None, "--json-out", help="Exporta el resultado a JSON."),
    html_out: Path | None = typer.Option(None, "--html-out", help="Exporta un reporte HTML seguro."),
    fail_under: int = typer.Option(0, "--fail-under", min=0, max=100, help="Falla con exit 1 si el puntaje es menor a este umbral (ideal para CI/CD)."),
) -> None:
    """Ejecuta una auditoría defensiva sobre URL y calcula una calificación de seguridad A–F."""
    target_url = _validate_url(url)

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, max_redirects=5) as client:
            response = client.get(target_url)
    except httpx.HTTPError as exc:
        console.print(f"[red]Error al conectar con {target_url}:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    final_url = str(response.url)
    is_https = final_url.lower().startswith("https://")
    tls_info = inspect_tls(final_url, timeout=timeout) if is_https else None

    findings = [
        *analyze_headers(response.headers, is_https=is_https),
        *analyze_cookies(response.headers.get_list("set-cookie"), is_https=is_https),
        *analyze_tls(tls_info, is_https=is_https),
    ]
    score, grade = compute_score_and_grade(findings)

    report = AuditReport(
        target_url=target_url,
        final_url=final_url,
        status_code=response.status_code,
        score=score,
        grade=grade,
        tls=tls_info,
        findings=findings,
    )

    _render_report(report)

    if json_out:
        export_json(report, json_out)
        console.print(f"[dim]Reporte JSON guardado en {json_out}[/dim]")
    if html_out:
        export_html(report, html_out)
        console.print(f"[dim]Reporte HTML guardado en {html_out}[/dim]")

    if report.score < fail_under:
        console.print(
            f"[red]Puntaje ({report.score}) inferior al umbral requerido ({fail_under}).[/red]"
        )
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
