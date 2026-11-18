import click
from collections import Counter
from rich.console import Console
from rich.table import Table

from hardener.analyzer import analyze_dockerfile
from hardener.scanner import scan_image
from hardener.config_scanner import scan_dockerfile_with_trivy
from hardener.exporter import export_findings
from hardener.score import calculate_hardening_score
from hardener.improvement import calculate_improvement_summary
from hardener.comparer import compare_xlsx_reports


console = Console()


@click.group()
def cli():
    """Docker Hardener CLI: herramienta para analizar y endurecer imágenes Docker."""
    pass


@cli.command()
@click.option('--file', '-f', type=click.Path(exists=True), help='Ruta al Dockerfile a analizar.')
@click.option('--image', '-i', help='Nombre de la imagen Docker a analizar.')
@click.option('--output', '-o', help='Ruta del archivo de salida. Ej: reports/report.xlsx')
@click.option('--limit', '-l', default=30, show_default=True, help='Cantidad máxima de hallazgos a mostrar en terminal.')

def scan(file, image, output,limit):
    """Ejecuta un análisis de seguridad sobre un Dockerfile o una imagen Docker."""

    console.print("[bold cyan]🚀 Iniciando análisis...[/bold cyan]")

    if not file and not image:
        console.print("[yellow]⚠️ No se especificó ni Dockerfile ni imagen. Usa --file o --image.[/yellow]")
        return

    # ============================================================
    # ANÁLISIS ESTÁTICO DE DOCKERFILE
    # ============================================================
    if file:
        console.print(f"[green]Analizando Dockerfile:[/green] {file}")

        custom_findings = analyze_dockerfile(file)

        try:
            trivy_findings = scan_dockerfile_with_trivy(file)
        except Exception as error:
            console.print(f"[yellow]⚠️ No se pudo ejecutar Trivy Config:[/yellow] {error}")
            trivy_findings = []

        findings = custom_findings + trivy_findings

        if not findings:
            console.print("[bold green]✅ No se encontraron hallazgos relevantes en el Dockerfile.[/bold green]")

            if output:
                try:
                    export_findings(findings, output)
                    console.print(f"[bold green]📄 Reporte exportado en:[/bold green] {output}")
                except Exception as error:
                    console.print(f"[bold red]❌ Error exportando reporte:[/bold red] {error}")

            return

        severity_counter = Counter(
            finding.get("severity", "UNKNOWN") for finding in findings
        )

        summary_table = Table(
            title="Resumen por severidad - Dockerfile",
            show_lines=True
        )

        summary_table.add_column("Severidad", style="bold")
        summary_table.add_column("Cantidad")

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            summary_table.add_row(
                severity,
                str(severity_counter.get(severity, 0))
            )

        console.print(summary_table)

        score_result = calculate_hardening_score(findings, analysis_type="dockerfile")

        score_table = Table(
            title="Hardening Score",
            show_lines=True
        )

        score_table.add_column("Métrica", style="bold")
        score_table.add_column("Valor")

        score_table.add_row("Score", f"{score_result['score']}/100")
        score_table.add_row("Nivel", score_result["level"])
        score_table.add_row("Hallazgos", str(score_result["total_findings"]))

        console.print(score_table)

        table = Table(
            title="Hallazgos de seguridad del Dockerfile",
            show_lines=True
        )

        table.add_column("Fuente")
        table.add_column("Severidad", style="bold")
        table.add_column("Regla")
        table.add_column("Descripción")
        table.add_column("Recomendación")
        table.add_column("Target")

        for finding in findings[:limit]:
            table.add_row(
                finding.get("source", "dockerhard rules"),
                finding.get("severity", "UNKNOWN"),
                finding.get("id", "N/A"),
                finding.get("description", "Sin descripción"),
                finding.get("recommendation", "Sin recomendación"),
                finding.get("target", file)
            )

        console.print(table)

        if output:
            try:
                export_findings(findings, output)
                console.print(f"[bold green]📄 Reporte exportado en:[/bold green] {output}")
            except Exception as error:
                console.print(f"[bold red]❌ Error exportando reporte:[/bold red] {error}")

    # ============================================================
    # ANÁLISIS DE IMAGEN DOCKER CON TRIVY
    # ============================================================
    if image:
        console.print(f"[green]Escaneando imagen Docker con Trivy:[/green] {image}")

        try:
            findings = scan_image(image)
        except Exception as error:
            console.print(f"[bold red]❌ Error escaneando imagen:[/bold red] {error}")
            return

        if not findings:
            console.print("[bold green]✅ No se encontraron vulnerabilidades en la imagen.[/bold green]")

            if output:
                try:
                    export_findings(findings, output)
                    console.print(f"[bold green]📄 Reporte exportado en:[/bold green] {output}")
                except Exception as error:
                    console.print(f"[bold red]❌ Error exportando reporte:[/bold red] {error}")

            return

        severity_counter = Counter(
            finding.get("severity", "UNKNOWN") for finding in findings
        )

        summary_table = Table(
            title="Resumen por severidad - Imagen Docker",
            show_lines=True
        )

        summary_table.add_column("Severidad", style="bold")
        summary_table.add_column("Cantidad")

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            summary_table.add_row(
                severity,
                str(severity_counter.get(severity, 0))
            )

        console.print(summary_table)

        score_result = calculate_hardening_score(findings, analysis_type="image")

        score_table = Table(
            title="Hardening Score",
            show_lines=True
        )

        score_table.add_column("Métrica", style="bold")
        score_table.add_column("Valor")

        score_table.add_row("Score", f"{score_result['score']}/100")
        score_table.add_row("Nivel", score_result["level"])
        score_table.add_row("Hallazgos", str(score_result["total_findings"]))

        console.print(score_table)

        table = Table(
            title="Vulnerabilidades detectadas en la imagen Docker",
            show_lines=True
        )

        table.add_column("Severidad", style="bold")
        table.add_column("CVE")
        table.add_column("Paquete")
        table.add_column("Instalada")
        table.add_column("Corregida")
        table.add_column("EPSS")
        table.add_column("Percentil")
        table.add_column("Target")
        table.add_column("Recomendación")

        for finding in findings[:limit]:
            table.add_row(
                finding.get("severity", "UNKNOWN"),
                finding.get("id", "N/A"),
                finding.get("package", "N/A"),
                finding.get("installed_version", "N/A"),
                finding.get("fixed_version", "No disponible"),
                str(finding.get("epss_score")) if finding.get("epss_score") is not None else "N/A",
                str(finding.get("epss_percentile")) if finding.get("epss_percentile") is not None else "N/A",
                finding.get("target", image),
                finding.get("recommendation", "Sin recomendación")
            )

        console.print(table)

        if len(findings) > limit:
            console.print(
                f"[yellow]⚠️ Se muestran {limit} de {len(findings)} hallazgos en terminal. "
                f"Use --output para exportar el reporte completo.[/yellow]"
    )

        if output:
            try:
                export_findings(findings, output)
                console.print(f"[bold green]📄 Reporte exportado en:[/bold green] {output}")
            except Exception as error:
                console.print(f"[bold red]❌ Error exportando reporte:[/bold red] {error}")


@cli.command()
@click.option(
    '--before',
    required=True,
    type=click.Path(exists=True),
    help='Reporte XLSX antes del hardening.'
)
@click.option(
    '--after',
    required=True,
    type=click.Path(exists=True),
    help='Reporte XLSX después del hardening.'
)
def compare(before, after):
    """Compara dos reportes XLSX generados por dockerhard."""

    result = compare_xlsx_reports(before, after)

    table = Table(
        title="Comparación Before vs After",
        show_lines=True
    )

    table.add_column("Métrica", style="bold")
    table.add_column("Valor")

    table.add_row("Hallazgos Antes", str(result["findings_before"]))
    table.add_row("Hallazgos Después", str(result["findings_after"]))
    table.add_row("Hallazgos Reducidos", str(result["findings_reduced"]))
    table.add_row("IMH (%)", str(result["imh"]))
    table.add_row("Nivel IMH", result["imh_level"])

    console.print(table)

if __name__ == '__main__':
    cli()