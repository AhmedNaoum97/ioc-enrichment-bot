from . import detector
from . import vt_client
from . import abuseipdb_client


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