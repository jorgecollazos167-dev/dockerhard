import argparse
from pathlib import Path
from collections import Counter, defaultdict

import matplotlib.pyplot as plt
from openpyxl import load_workbook


SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

SEVERITY_PENALTIES = {
    "CRITICAL": 15,
    "HIGH": 8,
    "MEDIUM": 4,
    "LOW": 0.3,
    "UNKNOWN": 2,
}


def load_xlsx_rows(path: str) -> list[dict]:
    wb = load_workbook(path, read_only=True)
    ws = wb.active

    rows = list(ws.iter_rows(values_only=True))

    if len(rows) < 2:
        return []

    headers = [
        str(cell).strip().lower() if cell else ""
        for cell in rows[0]
    ]

    data = []

    for row in rows[1:]:
        if not row or row[0] is None:
            continue

        first_value = str(row[0]).strip().lower()

        if first_value == "no se encontraron hallazgos.":
            continue

        item = {}

        for index, header in enumerate(headers):
            if header:
                item[header] = row[index] if index < len(row) else None

        data.append(item)

    return data


def get_value(row: dict, *keys, default=None):
    for key in keys:
        if key in row and row[key] not in [None, ""]:
            return row[key]
    return default


def severity_counts(rows: list[dict]) -> dict:
    counter = Counter()

    for row in rows:
        severity = str(
            get_value(row, "severity", "severidad", default="UNKNOWN")
        ).strip().upper()

        counter[severity] += 1

    return dict(counter)


def calculate_imh(before_total: int, after_total: int) -> float:
    if before_total <= 0:
        return 0.0

    return round(((before_total - after_total) / before_total) * 100, 2)


def calculate_adjusted_risk(row: dict) -> float:
    severity = str(
        get_value(row, "severity", "severidad", default="UNKNOWN")
    ).strip().upper()

    epss = get_value(row, "epss_score", "epss", "epss score", default=0)

    try:
        epss = float(epss)
    except (TypeError, ValueError):
        epss = 0.0

    base_penalty = SEVERITY_PENALTIES.get(severity, 2)

    return base_penalty * (1 + epss)


def save_chart(output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def chart_severity_distribution(rows: list[dict], output_path: Path, title: str):
    counts = severity_counts(rows)
    values = [counts.get(sev, 0) for sev in SEVERITIES]

    plt.figure(figsize=(9, 5))
    plt.bar(SEVERITIES, values)
    plt.xlabel("Severidad")
    plt.ylabel("Cantidad de hallazgos")
    plt.title(title)

    for index, value in enumerate(values):
        plt.text(index, value + 0.5, str(value), ha="center")

    save_chart(output_path)


def chart_sources(rows: list[dict], output_path: Path):
    counter = Counter()

    for row in rows:
        source = get_value(row, "source", "fuente", default="Sin fuente")
        counter[str(source)] += 1

    if not counter:
        return

    labels = list(counter.keys())
    values = list(counter.values())

    plt.figure(figsize=(9, 5))
    plt.bar(labels, values)
    plt.xlabel("Fuente")
    plt.ylabel("Cantidad de hallazgos")
    plt.title("Hallazgos por fuente de análisis")

    for index, value in enumerate(values):
        plt.text(index, value + 0.5, str(value), ha="center")

    save_chart(output_path)


def chart_top_rules(rows: list[dict], output_path: Path):
    counter = Counter()

    for row in rows:
        rule = get_value(row, "id", "regla", default="N/A")
        counter[str(rule)] += 1

    top_items = counter.most_common(10)

    if not top_items:
        return

    labels = [item[0] for item in top_items]
    values = [item[1] for item in top_items]

    plt.figure(figsize=(10, 7))
    plt.barh(labels[::-1], values[::-1])
    plt.xlabel("Cantidad")
    plt.ylabel("Regla")
    plt.title("Top 10 reglas con mayor recurrencia")

    save_chart(output_path)


def chart_top_packages(rows: list[dict], output_path: Path):
    counter = Counter()

    for row in rows:
        package = get_value(row, "package", "paquete", default="N/A")
        counter[str(package)] += 1

    top_items = counter.most_common(10)

    if not top_items:
        return

    labels = [item[0] for item in top_items]
    values = [item[1] for item in top_items]

    plt.figure(figsize=(10, 7))
    plt.barh(labels[::-1], values[::-1])
    plt.xlabel("Cantidad de vulnerabilidades")
    plt.ylabel("Paquete")
    plt.title("Top 10 paquetes con más vulnerabilidades")

    save_chart(output_path)


def chart_top_risk_packages(rows: list[dict], output_path: Path):
    package_risk = defaultdict(float)

    for row in rows:
        package = get_value(row, "package", "paquete", default="N/A")
        package_risk[str(package)] += calculate_adjusted_risk(row)

    top_items = sorted(
        package_risk.items(),
        key=lambda item: item[1],
        reverse=True
    )[:10]

    if not top_items:
        return

    labels = [item[0] for item in top_items]
    values = [round(item[1], 2) for item in top_items]

    plt.figure(figsize=(10, 7))
    plt.barh(labels[::-1], values[::-1])
    plt.xlabel("Riesgo residual ajustado")
    plt.ylabel("Paquete")
    plt.title("Top 10 paquetes por riesgo ajustado")

    for index, value in enumerate(values[::-1]):
        plt.text(value, index, f"{value:.2f}", va="center")

    save_chart(output_path)


def chart_severity_before_after(before_rows, after_rows, output_path: Path):
    before_counts = severity_counts(before_rows)
    after_counts = severity_counts(after_rows)

    before_values = [before_counts.get(sev, 0) for sev in SEVERITIES]
    after_values = [after_counts.get(sev, 0) for sev in SEVERITIES]

    x = range(len(SEVERITIES))
    width = 0.35

    plt.figure(figsize=(11, 6))
    plt.bar([i - width / 2 for i in x], before_values, width, label="Antes")
    plt.bar([i + width / 2 for i in x], after_values, width, label="Después")

    plt.xticks(list(x), SEVERITIES)
    plt.xlabel("Severidad")
    plt.ylabel("Cantidad de hallazgos")
    plt.title("Hallazgos por severidad antes y después")
    plt.legend()

    save_chart(output_path)


def chart_reduction_by_severity(before_rows, after_rows, output_path: Path):
    before_counts = severity_counts(before_rows)
    after_counts = severity_counts(after_rows)

    reductions = []

    for severity in SEVERITIES:
        before = before_counts.get(severity, 0)
        after = after_counts.get(severity, 0)

        if before == 0:
            reduction = 0
        else:
            reduction = ((before - after) / before) * 100

        reductions.append(round(reduction, 2))

    plt.figure(figsize=(10, 6))
    plt.plot(SEVERITIES, reductions, marker="o")
    plt.ylim(0, 100)
    plt.xlabel("Severidad")
    plt.ylabel("Reducción (%)")
    plt.title("Reducción porcentual por severidad")

    for index, value in enumerate(reductions):
        plt.text(index, value + 2, f"{value:.2f}%", ha="center")

    save_chart(output_path)


def chart_imh(case_name: str, before_rows, after_rows, output_path: Path):
    before_total = len(before_rows)
    after_total = len(after_rows)
    imh = calculate_imh(before_total, after_total)

    plt.figure(figsize=(7, 5))
    plt.bar([case_name], [imh])
    plt.ylim(0, 100)
    plt.ylabel("IMH (%)")
    plt.title("Índice de Mejora de Hardening")

    plt.text(0, min(imh + 2, 98), f"{imh:.2f}%", ha="center")

    save_chart(output_path)


def run_static(args):
    rows = load_xlsx_rows(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    chart_severity_distribution(
        rows,
        output_dir / "01_static_severity_distribution.png",
        "Distribución de hallazgos estáticos por severidad"
    )

    chart_sources(
        rows,
        output_dir / "02_static_sources.png"
    )

    chart_top_rules(
        rows,
        output_dir / "03_static_top_rules.png"
    )

    print("Gráficas estáticas generadas en:", output_dir)


def run_dynamic(args):
    rows = load_xlsx_rows(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    chart_severity_distribution(
        rows,
        output_dir / "01_dynamic_severity_distribution.png",
        "Distribución de vulnerabilidades por severidad"
    )

    chart_top_packages(
        rows,
        output_dir / "02_dynamic_top_packages.png"
    )

    chart_top_risk_packages(
        rows,
        output_dir / "03_dynamic_top_risk_packages.png"
    )

    print("Gráficas dinámicas generadas en:", output_dir)


def run_compare(args):
    before_rows = load_xlsx_rows(args.before)
    after_rows = load_xlsx_rows(args.after)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    chart_severity_before_after(
        before_rows,
        after_rows,
        output_dir / "01_compare_severity_before_after.png"
    )

    chart_reduction_by_severity(
        before_rows,
        after_rows,
        output_dir / "02_compare_reduction_by_severity.png"
    )

    chart_imh(
        args.case,
        before_rows,
        after_rows,
        output_dir / "03_compare_imh.png"
    )

    print("Gráficas comparativas generadas en:", output_dir)


def main():
    parser = argparse.ArgumentParser(
        description="Generador de gráficas para reportes XLSX de dockerhard."
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    static_parser = subparsers.add_parser(
        "static",
        help="Genera gráficas del análisis estático de Dockerfile."
    )
    static_parser.add_argument("--input", required=True)
    static_parser.add_argument("--output-dir", required=True)
    static_parser.set_defaults(func=run_static)

    dynamic_parser = subparsers.add_parser(
        "dynamic",
        help="Genera gráficas del análisis dinámico de imagen Docker."
    )
    dynamic_parser.add_argument("--input", required=True)
    dynamic_parser.add_argument("--output-dir", required=True)
    dynamic_parser.set_defaults(func=run_dynamic)

    compare_parser = subparsers.add_parser(
        "compare",
        help="Genera gráficas comparativas Before vs After."
    )
    compare_parser.add_argument("--before", required=True)
    compare_parser.add_argument("--after", required=True)
    compare_parser.add_argument("--case", required=True)
    compare_parser.add_argument("--output-dir", required=True)
    compare_parser.set_defaults(func=run_compare)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()