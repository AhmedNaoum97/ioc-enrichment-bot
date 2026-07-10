import os
import requests
from dotenv import load_dotenv

load_dotenv()  # reads .env into environment variables

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def lookup_abuseipdb(indicator: str) -> dict | None:
    """Look up an IP address on AbuseIPDB and return a summary dict."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        raise ValueError("AbuseIPDB API key not found in environment variables.")

    response = requests.get(
        ABUSEIPDB_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": indicator, "maxAgeInDays": 90},
    )

    if response.status_code == 404:
        return None
    response.raise_for_status()

    data = response.json()["data"]
    return {
        "abuse_confidence": data["abuseConfidenceScore"],
        "total_reports": data["totalReports"],
        "country": data["countryCode"],
        "isp": data["isp"],
    }