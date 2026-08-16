"""DoH unit tests stub the network layer; we don't hit Cloudflare in CI."""
from unittest import mock

import pytest

from nearest_exit import doh


@pytest.fixture(autouse=True)
def _clear_doh_cache():
    """resolve_a memoizes in-process; keep every test hermetic."""
    doh.clear_cache()
    yield
    doh.clear_cache()


def _fake_urlopen(payload):
    """Patch the transport so json.load() in resolve_a sees `payload`."""
    cm = mock.MagicMock()
    cm.__enter__.return_value = mock.MagicMock(read=lambda: b"")
    return mock.patch.object(doh.urllib.request, "urlopen", return_value=cm)


def test_resolve_a_parses_answer():
    fake_payload = {
        "Status": 0,
        "Answer": [
            {"name": "example.com.", "type": 1, "TTL": 60, "data": "93.184.216.34"},
            {"name": "example.com.", "type": 28, "TTL": 60, "data": "2606:..."},
        ],
    }
    with mock.patch.object(doh, "urllib") as u:
        cm = mock.MagicMock()
        cm.__enter__.return_value = mock.MagicMock(read=lambda: b"")
        u.request.urlopen.return_value = cm
        with mock.patch.object(doh.json, "load", return_value=fake_payload):
            ips = doh.resolve_a("example.com")
    assert ips == ["93.184.216.34"]


def test_resolve_a_empty_on_error():
    with mock.patch.object(doh.urllib.request, "urlopen", side_effect=OSError("no net")):
        assert doh.resolve_a("example.com") == []


def test_resolve_a_memoizes_positive_result():
    payload = {"Answer": [{"type": 1, "data": "1.2.3.4"}]}
    with _fake_urlopen(payload) as opener:
        with mock.patch.object(doh.json, "load", return_value=payload):
            assert doh.resolve_a("relay.example") == ["1.2.3.4"]
            assert doh.resolve_a("relay.example") == ["1.2.3.4"]
            assert doh.resolve_a("relay.example") == ["1.2.3.4"]
    assert opener.call_count == 1


def test_resolve_a_caches_per_hostname():
    payload = {"Answer": [{"type": 1, "data": "1.2.3.4"}]}
    with _fake_urlopen(payload) as opener:
        with mock.patch.object(doh.json, "load", return_value=payload):
            doh.resolve_a("a.example")
            doh.resolve_a("b.example")
    assert opener.call_count == 2


def test_clear_cache_forces_requery():
    payload = {"Answer": [{"type": 1, "data": "1.2.3.4"}]}
    with _fake_urlopen(payload) as opener:
        with mock.patch.object(doh.json, "load", return_value=payload):
            doh.resolve_a("relay.example")
            doh.clear_cache()
            doh.resolve_a("relay.example")
    assert opener.call_count == 2


def test_negative_results_expire_sooner_than_positive():
    assert doh.NEGATIVE_TTL_S < doh.POSITIVE_TTL_S


def test_failed_lookup_is_retried_after_negative_ttl(monkeypatch):
    monkeypatch.setattr(doh, "NEGATIVE_TTL_S", 0.0)
    with mock.patch.object(doh.urllib.request, "urlopen", side_effect=OSError) as opener:
        assert doh.resolve_a("dead.example") == []
        assert doh.resolve_a("dead.example") == []
    assert opener.call_count == 2


def test_cached_list_is_not_shared_with_caller():
    payload = {"Answer": [{"type": 1, "data": "1.2.3.4"}]}
    with _fake_urlopen(payload):
        with mock.patch.object(doh.json, "load", return_value=payload):
            first = doh.resolve_a("relay.example")
            first.append("9.9.9.9")
            assert doh.resolve_a("relay.example") == ["1.2.3.4"]
