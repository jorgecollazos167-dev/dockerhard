from collections import Counter


def calculate_hardening_score(findings: list[dict], analysis_type: str = "dockerfile") -> dict:
    if not findings:
        return {
            "score": 100,
            "level": "Endurecimiento Óptimo",
            "total_findings": 0,
            "weighted_risk": 0
        }

    severity_penalties = {
        "CRITICAL": 15,
        "HIGH": 8,
        "MEDIUM": 4,
        "LOW": 0.3,
        "UNKNOWN": 2
    }

    total_penalty = 0

    for finding in findings:
        severity = finding.get("severity", "UNKNOWN").upper()
        base_penalty = severity_penalties.get(severity, 2)

        if analysis_type == "image":
            epss_score = get_epss_score(finding)
            penalty = base_penalty * (1 + epss_score)
        else:
            penalty = base_penalty

        total_penalty += penalty

    score = 100 / (1 + (total_penalty / 100))

    return {
        "score": round(score, 2),
        "level": classify_score(score),
        "total_findings": len(findings),
        "weighted_risk": round(total_penalty, 2),
        "severity_summary": dict(
            Counter(
                finding.get("severity", "UNKNOWN").upper()
                for finding in findings
            )
        )
    }


def get_epss_score(finding: dict) -> float:
    epss_value = (
        finding.get("epss_score")
        or finding.get("epss")
        or finding.get("EPSS")
        or 0
    )

    try:
        return float(epss_value)
    except (ValueError, TypeError):
        return 0.0


def classify_score(score: float) -> str:
    if score >= 90:
        return "Endurecimiento Óptimo"
    elif score >= 75:
        return "Endurecimiento Adecuado"
    elif score >= 60:
        return "Endurecimiento Parcial"
    elif score >= 40:
        return "Alto Riesgo de Exposición"
    else:
        return "Exposición Crítica"