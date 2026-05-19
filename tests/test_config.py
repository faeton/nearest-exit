from nearest_exit.config import Config, validate_config


def test_validate_config_reports_common_mistakes():
    cfg = Config()
    cfg.providers.order = ["nordvpn", "bogusvpn"]
    cfg.providers.weights = {"nordvpn": 1.0, "ghostvpn": 0.5, "pia": 0.0}
    cfg.providers.others_threshold_ms = -1.0
    cfg.defaults.scope = "region"
    cfg.defaults.count = 0
    cfg.geo.lookup = "ipapi"

    warnings = validate_config(cfg, ["nordvpn", "airvpn", "mullvad", "pia"])

    assert any("unknown provider(s)" in w for w in warnings)
    assert any("unknown provider weight(s)" in w for w in warnings)
    assert any("provider weight for pia" in w for w in warnings)
    assert any("others_threshold_ms" in w for w in warnings)
    assert any("defaults.scope" in w for w in warnings)
    assert any("defaults.count" in w for w in warnings)
    assert any("geo.lookup" in w for w in warnings)


def test_validate_config_accepts_defaults():
    assert validate_config(Config(), ["nordvpn", "airvpn", "mullvad", "pia"]) == []
