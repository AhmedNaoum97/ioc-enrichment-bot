from ioc_bot import abuseipdb_client, vt_client
from ioc_bot.verdict import enrich

def fail_if_called(*args, **kwargs):
    raise AssertionError("API should not have been called")


def test_unknown_input_skips_lookups(monkeypatch):
    monkeypatch.setattr(vt_client, "lookup_virustotal", fail_if_called)
    monkeypatch.setattr(abuseipdb_client, "lookup_abuseipdb", fail_if_called)

    result = enrich("not an indicator!!!")

    assert result["type"] == "unknown"
    assert result["verdict"] == "unknown"


def test_private_ip_is_internal_and_skips_lookups(monkeypatch):
    monkeypatch.setattr(vt_client, "lookup_virustotal", fail_if_called)
    monkeypatch.setattr(abuseipdb_client, "lookup_abuseipdb", fail_if_called)

    result = enrich("192.168.1.10")

    assert result["type"] == "ip"
    assert result["verdict"] == "internal"


def test_domain_skips_abuseipdb(monkeypatch):
    monkeypatch.setattr(vt_client, "lookup_virustotal", lambda i, t: {"malicious": 7})
    monkeypatch.setattr(abuseipdb_client, "lookup_abuseipdb", fail_if_called)

    result = enrich("https://evil.com:443/login")

    assert result["indicator"] == "evil.com"
    assert result["type"] == "domain"
    assert result["verdict"] == "malicious"



def test_worst_verdict_wins(monkeypatch):
    monkeypatch.setattr(vt_client, "lookup_virustotal", lambda i, t: {"malicious": 0})
    monkeypatch.setattr(abuseipdb_client, "lookup_abuseipdb", lambda i: {"abuse_confidence": 80})

    result = enrich("8.8.8.8")

    assert result["verdict"] == "malicious"


def test_not_found_anywhere_is_unknown(monkeypatch):
    monkeypatch.setattr(vt_client, "lookup_virustotal", lambda i, t: None)
    monkeypatch.setattr(abuseipdb_client, "lookup_abuseipdb", lambda i: None)

    result = enrich("8.8.8.8")

    assert result["verdict"] == "unknown"