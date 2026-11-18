import json
import shutil
import subprocess


def check_trivy_installed() -> None:
    if shutil.which("trivy") is None:
        raise RuntimeError("Trivy no está instalado o no está disponible en el PATH.")


def run_trivy_config_scan(file_path: str) -> dict:
    check_trivy_installed()

    command = [
        "trivy",
        "config",
        "--format",
        "json",
        file_path
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode not in [0, 1]:
        raise RuntimeError(result.stderr.strip())

    return json.loads(result.stdout)


def parse_trivy_config_results(trivy_data: dict) -> list[dict]:
    findings = []

    for result in trivy_data.get("Results", []):
        target = result.get("Target", "N/A")

        for misconf in result.get("Misconfigurations", []) or []:
            findings.append({
                "id": misconf.get("ID", "N/A"),
                "source": "Trivy Config",
                "severity": misconf.get("Severity", "UNKNOWN"),
                "description": misconf.get("Title", "Sin descripción"),
                "recommendation": misconf.get("Resolution", "Revisar configuración del Dockerfile."),
                "target": target,
                "type": "dockerfile-config"
            })

    return findings


def scan_dockerfile_with_trivy(file_path: str) -> list[dict]:
    trivy_data = run_trivy_config_scan(file_path)
    return parse_trivy_config_results(trivy_data)