import json
import shutil
import subprocess
from hardener.recommender import generate_vulnerability_recommendation
from hardener.enricher import enrich_vulnerability



def check_trivy_installed() -> None:
    if shutil.which("trivy") is None:
        raise RuntimeError(
            "Trivy no está instalado o no está disponible en el PATH."
        )


def run_trivy_scan(image_name: str) -> dict:
    check_trivy_installed()

    command = [
        "trivy",
        "image",
        "--format",
        "json",
        image_name
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    return json.loads(result.stdout)


def parse_trivy_results(trivy_data: dict) -> list[dict]:
    findings = []

    for result in trivy_data.get("Results", []):
        target = result.get("Target", "N/A")
        result_type = result.get("Type", "N/A")

        vulnerabilities = result.get("Vulnerabilities", []) or []

        for vuln in vulnerabilities:
            fixed_version = vuln.get("FixedVersion", "")
            enrichment = enrich_vulnerability(vuln)
            findings.append({
                "id": vuln.get("VulnerabilityID", "N/A"),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "package": vuln.get("PkgName", "N/A"),
                "installed_version": vuln.get("InstalledVersion", "N/A"),
                "fixed_version": fixed_version if fixed_version else "No disponible",
                "target": target,
                "type": result_type,
                "description": vuln.get("Title", "Sin descripción"),
                "epss_score": enrichment.get("epss_score"),
                "epss_percentile": enrichment.get("epss_percentile"),
                "recommendation": generate_vulnerability_recommendation(vuln)
            })

    return findings

    



def scan_image(image_name: str) -> list[dict]:
    trivy_data = run_trivy_scan(image_name)
    return parse_trivy_results(trivy_data)
