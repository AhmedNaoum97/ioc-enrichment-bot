from . import detector
from . import vt_client
from . import abuseipdb_client


SEVERITY = {"clean": 0,
            "suspicious": 1,
            "malicious": 2,
            } # For comparing verdicts

def vt_verdict(vt_stats: dict | None) -> str | None:
    if vt_stats is None:
        return None

    malicious = vt_stats["malicious"]

    if malicious >= 5:
        return "malicious"
    if malicious >= 1:
        return "suspicious"
    return "clean"