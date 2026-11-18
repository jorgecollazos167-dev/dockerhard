import json
from pathlib import Path
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment


def export_findings(findings: list[dict], output_path: str) -> None:
    path = Path(output_path)
    extension = path.suffix.lower()

    if extension == ".json":
        export_json(findings, path)
    elif extension == ".xlsx":
        export_xlsx(findings, path)
    else:
        raise ValueError("Formato no soportado. Use .json o .xlsx")


def export_json(findings: list[dict], path: Path) -> None:
    with path.open("w", encoding="utf-8") as file:
        json.dump(findings, file, indent=4, ensure_ascii=False)


def export_xlsx(findings: list[dict], path: Path) -> None:
    wb = Workbook()
    ws = wb.active
    ws.title = "Hallazgos"

    if not findings:
        ws.append(["Mensaje"])
        ws.append(["No se encontraron hallazgos."])
        wb.save(path)
        return

    headers = sorted({
        key
        for finding in findings
        for key in finding.keys()
    })

    ws.append(headers)

    header_fill = PatternFill("solid", fgColor="1F4E78")
    header_font = Font(color="FFFFFF", bold=True)

    for cell in ws[1]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", vertical="center")

    for finding in findings:
        ws.append([
            finding.get(header, "")
            for header in headers
        ])

    for column in ws.columns:
        max_length = 0
        column_letter = column[0].column_letter

        for cell in column:
            value = str(cell.value) if cell.value is not None else ""
            max_length = max(max_length, len(value))

        ws.column_dimensions[column_letter].width = min(max_length + 2, 60)

    ws.auto_filter.ref = ws.dimensions
    ws.freeze_panes = "A2"

    wb.save(path)