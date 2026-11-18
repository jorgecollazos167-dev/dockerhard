import requests


def get_epss_data(cve_id: str) -> dict:
    url = "https://api.first.org/data/v1/epss"

    try:
        response = requests.get(
            url,
            params={"cve": cve_id},
            timeout=10
        )
        response.raise_for_status()

        data = response.json()
        records = data.get("data", [])

        if not records:
            return {
                "epss_score": None,
                "epss_percentile": None
            }

        record = records[0]

        return {
            "epss_score": float(record.get("epss", 0)),
            "epss_percentile": float(record.get("percentile", 0))
        }

    except Exception:
        return {
            "epss_score": None,
            "epss_percentile": None
        }


def enrich_vulnerability(vuln: dict) -> dict:
    cve_id = vuln.get("VulnerabilityID", "")

    enrichment = {
        "epss_score": None,
        "epss_percentile": None
    }

    if cve_id.startswith("CVE-"):
        enrichment.update(get_epss_data(cve_id))

    return enrichment