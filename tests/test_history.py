from nearest_exit.history import (
    network_fingerprint,
    record_scan,
    recent_winners,
    sticky_bonus,
)


def test_fingerprint_stable_for_same_input():
    a = network_fingerprint("AS9009")
    b = network_fingerprint("AS9009")
    assert a == b
    assert len(a) == 16


def test_fingerprint_differs_per_asn():
    assert network_fingerprint("AS9009") != network_fingerprint("AS3320")


def test_record_and_query_winners(tmp_path):
    db = tmp_path / "h.sqlite"
    fp = "test-fp"
    rows = [
        {
            "provider": "nordvpn", "relay_id": "ro78", "hostname": "ro78.nordvpn.com",
            "country_code": "ro", "rtt_ms": 20.0, "loss": 0.0, "jitter_ms": 1.0,
            "success": True, "rank": 1,
        },
        {
            "provider": "mullvad", "relay_id": "se-sto-wg-001",
            "hostname": "se-sto-wg-001", "country_code": "se",
            "rtt_ms": 35.0, "loss": 0.0, "jitter_ms": 2.0,
            "success": True, "rank": 2,
        },
    ]
    record_scan(rows, fp, db_path=db)
    record_scan(rows, fp, db_path=db)  # second run, same winner

    winners = recent_winners(fp, since_seconds=3600, db_path=db)
    assert winners[("nordvpn", "ro78")] == 2
    assert ("mullvad", "se-sto-wg-001") not in winners


def test_sticky_bonus_caps():
    winners = {("nordvpn", "ro78"): 100}
    assert sticky_bonus("nordvpn", "ro78", winners) == 8.0
    assert sticky_bonus("mullvad", "x", winners) == 0.0
    winners2 = {("nordvpn", "ro78"): 1}
    assert sticky_bonus("nordvpn", "ro78", winners2) == 3.0
