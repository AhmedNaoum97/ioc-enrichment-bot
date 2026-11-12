from ioc_bot.verdict import vt_verdict, abuse_verdict


# --- VirusTotal verdict ---

def test_vt_none_returns_none():
    assert vt_verdict(None) is None

def test_zero_is_clean():
    assert vt_verdict({"malicious": 0}) == "clean"

def test_one_is_suspicious():
    assert vt_verdict({"malicious": 1}) == "suspicious"

def test_four_is_suspicious():
    assert vt_verdict({"malicious": 4}) == "suspicious"

def test_five_is_malicious():
    assert vt_verdict({"malicious": 5}) == "malicious"


# --- AbuseIPDB verdict ---

def test_abuse_none_returns_none():
    assert abuse_verdict(None) is None

def test_abuse_zero_is_clean():
    assert abuse_verdict({"abuse_confidence": 0}) == "clean"

def test_abuse_24_is_clean():
    assert abuse_verdict({"abuse_confidence": 24}) == "clean"

def test_abuse_25_is_suspicious():
    assert abuse_verdict({"abuse_confidence": 25}) == "suspicious"

def test_abuse_74_is_suspicious():
    assert abuse_verdict({"abuse_confidence": 74}) == "suspicious"

def test_abuse_75_is_malicious():
    assert abuse_verdict({"abuse_confidence": 75}) == "malicious"