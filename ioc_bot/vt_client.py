import os
import requests
from dotenv import load_dotenv

load_dotenv() # Reads .env into env variables

VT_BASE = "https://www.virustotal.com/api/v3"


ENDPOINTS = {
    "ip": "ip_addresses",
    "domain": "domains",
    "hash": "files",
}

def lookup_virustotal(indicator: str, indicator_type: str) -> dict | None:
    """Lookup an indicator in VirusTotal and return the JSON response."""
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        raise ValueError("VirusTotal API key not found in environment variables.")

    endpoint = ENDPOINTS.get(indicator_type)
    if not endpoint:
        raise ValueError(f"Unsupported indicator type: {indicator_type}")
    url = f"{VT_BASE}/{endpoint}/{indicator}"
    response = requests.get(url, headers={"x-apikey": os.getenv("VT_API_KEY")})
    if response.status_code == 404:
        return None # Indicator unknown to VirusTotal
    response.raise_for_status() # Raise an error for other HTTP errors
    return response.json()["data"]["attributes"]["last_analysis_stats"]
