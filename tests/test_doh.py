"""DoH unit tests stub the network layer; we don't hit Cloudflare in CI."""
from unittest import mock

from nearest_exit import doh


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
