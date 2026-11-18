def calculate_imh(findings_before: int, findings_after: int) -> float:
    """
    Calcula el Índice de Mejora de Hardening (IMH).

    Fórmula:
    IMH = ((Hallazgos Antes - Hallazgos Después) / Hallazgos Antes) * 100
    """

    if findings_before <= 0:
        return 0.0

    imh = ((findings_before - findings_after) / findings_before) * 100

    return round(imh, 2)


def classify_imh(imh: float) -> str:
    """
    Clasifica el nivel de mejora alcanzado después del hardening.
    """

    if imh >= 90:
        return "Mejora Excelente"

    if imh >= 75:
        return "Mejora Muy Alta"

    if imh >= 50:
        return "Mejora Alta"

    if imh >= 25:
        return "Mejora Moderada"

    if imh > 0:
        return "Mejora Baja"

    if imh == 0:
        return "Sin Mejora"

    return "Deterioro de Seguridad"


def calculate_improvement_summary(
    findings_before: int,
    findings_after: int,
    score_before: float | None = None,
    score_after: float | None = None
) -> dict:
    """
    Genera un resumen completo de mejora entre un estado inicial y uno posterior.
    """

    imh = calculate_imh(findings_before, findings_after)

    summary = {
        "findings_before": findings_before,
        "findings_after": findings_after,
        "findings_reduced": findings_before - findings_after,
        "imh": imh,
        "imh_level": classify_imh(imh)
    }

    if score_before is not None and score_after is not None:
        summary["score_before"] = score_before
        summary["score_after"] = score_after
        summary["score_delta"] = round(score_after - score_before, 2)

    return summary