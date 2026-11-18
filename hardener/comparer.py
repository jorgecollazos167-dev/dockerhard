from openpyxl import load_workbook
from hardener.improvement import calculate_improvement_summary


def count_findings_from_xlsx(file_path: str) -> int:

    wb = load_workbook(file_path, read_only=True)
    ws = wb.active

    findings = 0

    for row in ws.iter_rows(min_row=2, values_only=True):

        if not row:
            continue

        if row[0] is None:
            continue

        value = str(row[0]).strip().lower()

        if value == "no se encontraron hallazgos.":
            return 0

        findings += 1

    return findings


def compare_xlsx_reports(before_path: str, after_path: str) -> dict:

    findings_before = count_findings_from_xlsx(before_path)
    findings_after = count_findings_from_xlsx(after_path)

    return calculate_improvement_summary(
        findings_before=findings_before,
        findings_after=findings_after
    )