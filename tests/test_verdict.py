from ioc_bot.verdict import vt_verdict



def test_five_is_malicious():
    assert vt_verdict({"malicious": 5}) == "malicious"

def test_four_is_suspicious():
    assert vt_verdict({"malicious": 4}) == "suspicious"

def test_one_is_suspicious():
    assert vt_verdict({"malicious": 1}) == "suspicious"

def test_zero_is_clean():
    assert vt_verdict({"malicious": 0}) == "clean"

def test_none_returns_none():
    assert vt_verdict(None) is None