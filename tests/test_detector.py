from ioc_bot.detector import detect_indicator_type, normalize_indicator


# --- Type detection ---

def test_ipv4():
    assert detect_indicator_type("8.8.8.8") == "ip"

def test_ipv6():
    assert detect_indicator_type("::1") == "ip"

def test_md5_hash():
    assert detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"

def test_sha1_hash():
    assert detect_indicator_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"

def test_sha256_hash():
    assert detect_indicator_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"

def test_domain():
    assert detect_indicator_type("github.com") == "domain"

def test_url_stripped_to_domain():
    assert detect_indicator_type("https://evil.com/path ") == "domain"

def test_url_with_ip():
    assert detect_indicator_type("http://192.168.1.1/admin") == "ip"

def test_garbage_is_unknown():
    assert detect_indicator_type("not an indicator!!!") == "unknown"

def test_bare_scheme_is_unknown():
    assert detect_indicator_type("http://") == "unknown"

def test_url_with_ip_and_port():
    assert detect_indicator_type("http://1.2.3.4:8080/admin") == "ip"

def test_url_with_domain_and_port():
    assert detect_indicator_type("https://example.com:8080/path") == "domain"


# --- Normalization ---

def test_normalize_url_to_host():
    assert normalize_indicator("  HTTPS://Evil.com:443/login ") == "evil.com"

def test_normalize_plain_ip_unchanged():
    assert normalize_indicator("8.8.8.8") == "8.8.8.8"

def test_normalize_bare_scheme_is_empty():
    assert normalize_indicator("http://") == ""