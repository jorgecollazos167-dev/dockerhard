from pathlib import Path
from hardener.rules import RULES


def load_dockerfile(file_path: str) -> list[str]:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"No se encontró el archivo: {file_path}")

    with path.open("r", encoding="utf-8") as file:
        return file.readlines()


def normalize_lines(lines: list[str]) -> list[str]:
    normalized = []

    for line in lines:
        clean_line = line.strip()

        if not clean_line:
            continue

        if clean_line.startswith("#"):
            continue

        normalized.append(clean_line)

    return normalized


def analyze_dockerfile(file_path: str) -> list[dict]:
    raw_lines = load_dockerfile(file_path)
    lines = normalize_lines(raw_lines)

    findings = []

    for rule in RULES:
        if rule["check"](lines):
            findings.append({
                "id": rule["id"],
                "severity": rule["severity"],
                "description": rule["description"],
                "recommendation": rule["recommendation"]
            })

    return findings