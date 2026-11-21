import ipaddress

from . import abuseipdb_client
from . import detector
from . import vt_client


SEVERITY = {
    "clean": 0,
    "suspicious": 1,
    "malicious": 2,
}  # For comparing verdicts


def vt_verdict(vt_stats: dict | None) -> str | None:
    """Turn VirusTotal detection stats into a verdict."""
    if vt_stats is None:
        return None

    malicious = vt_stats["malicious"]

    if malicious >= 5:
        return "malicious"
    if malicious >= 1:
        return "suspicious"
    return "clean"


def abuse_verdict(abuse_data: dict | None) -> str | None:
    """Turn an AbuseIPDB summary into a verdict."""
    if abuse_data is None:
        return None

    confidence = abuse_data["abuse_confidence"]

    if confidence >= 75:
        return "malicious"
    if confidence >= 25:
        return "suspicious"
    return "clean"


def enrich(raw: str) -> dict:
    """Normalize, classify, look up, and return a combined verdict for one IOC."""
    indicator = detector.normalize_indicator(raw)
    ioc_type = detector.detect_indicator_type(indicator)

    result = {
        "indicator": indicator,
        "type": ioc_type,
        "virustotal": None,
        "abuseipdb": None,
        "verdict": "unknown",
    }

    if ioc_type == "unknown":
        return result

    if ioc_type == "ip" and not ipaddress.ip_address(indicator).is_global:
        result["verdict"] = "internal"
        return result

    result["virustotal"] = vt_client.lookup_virustotal(indicator, ioc_type)

    if ioc_type == "ip":
        result["abuseipdb"] = abuseipdb_client.lookup_abuseipdb(indicator)

    verdicts = [
        v
        for v in (vt_verdict(result["virustotal"]), abuse_verdict(result["abuseipdb"]))
        if v is not None
    ]
    if verdicts:
        result["verdict"] = max(verdicts, key=SEVERITY.get)

    return result