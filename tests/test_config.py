import math

import pytest

from nearest_exit.config import MAX_WEIGHT, Config, load_config, validate_config

PROVIDERS = ["nordvpn", "airvpn", "mullvad", "pia"]


def test_validate_config_reports_common_mistakes():
    cfg = Config()
    cfg.providers.order = ["nordvpn", "bogusvpn"]
    cfg.providers.weights = {"nordvpn": 1.0, "ghostvpn": 0.5, "pia": 0.0}
    cfg.providers.others_threshold_ms = -1.0
    cfg.defaults.scope = "region"
    cfg.defaults.count = 0
    cfg.geo.lookup = "ipapi"

    warnings = validate_config(cfg, PROVIDERS)

    assert any("unknown provider(s)" in w for w in warnings)
    assert any("unknown provider weight(s)" in w for w in warnings)
    assert any("provider weight for pia" in w for w in warnings)
    assert any("others_threshold_ms" in w for w in warnings)
    assert any("defaults.scope" in w for w in warnings)
    assert any("defaults.count" in w for w in warnings)
    assert any("geo.lookup" in w for w in warnings)


def test_validate_config_accepts_defaults():
    assert validate_config(Config(), PROVIDERS) == []


def test_validate_config_rejects_non_finite_weight():
    cfg = Config()
    cfg.providers.weights = {"mullvad": math.inf}
    warnings = validate_config(cfg, PROVIDERS)
    assert any("positive number" in w for w in warnings)


def _write(tmp_path, body: str):
    p = tmp_path / "config.toml"
    p.write_text(body)
    return p


def test_load_config_coerces_quoted_scalars_instead_of_crashing(tmp_path):
    """A quoted number used to load as `str` and make every command traceback."""
    cfg = load_config(_write(tmp_path, '[defaults]\ntop = "3"\ntimeout = "1.5"\n'))

    assert cfg.defaults.top == 3
    assert cfg.defaults.timeout == 1.5
    assert any("quoted" in e for e in cfg.load_errors)
    # The whole point: validation now runs without raising.
    assert validate_config(cfg, PROVIDERS) == cfg.load_errors


def test_load_config_keeps_default_when_value_is_unusable(tmp_path):
    cfg = load_config(_write(tmp_path, '[defaults]\ntop = "three"\n'))

    assert cfg.defaults.top == Config().defaults.top
    assert any("defaults.top" in e for e in cfg.load_errors)


def test_load_config_drops_non_finite_and_negative_weights(tmp_path):
    cfg = load_config(
        _write(tmp_path, '[providers]\nweights = { mullvad = "inf", pia = -1.0 }\n')
    )

    assert "mullvad" not in cfg.providers.weights
    assert "pia" not in cfg.providers.weights
    assert any("finite" in e for e in cfg.load_errors)
    assert any("must be > 0" in e for e in cfg.load_errors)


def test_load_config_clamps_extreme_weights(tmp_path):
    """An unbounded weight let one provider win regardless of measurement."""
    cfg = load_config(_write(tmp_path, "[providers]\nweights = { nordvpn = 1e9 }\n"))

    assert cfg.providers.weights["nordvpn"] == MAX_WEIGHT
    assert any("clamped" in e for e in cfg.load_errors)


def test_load_config_survives_malformed_toml(tmp_path):
    cfg = load_config(_write(tmp_path, "[providers\norder = "))

    assert cfg.providers.order == Config().providers.order
    assert any("could not read" in e for e in cfg.load_errors)


@pytest.mark.parametrize(
    "body,attr,expected",
    [
        ('[providers]\nothers_allowed = "false"\n', "others_allowed", False),
        ("[providers]\nothers_allowed = false\n", "others_allowed", False),
    ],
)
def test_load_config_coerces_booleans(tmp_path, body, attr, expected):
    cfg = load_config(_write(tmp_path, body))
    assert getattr(cfg.providers, attr) is expected
