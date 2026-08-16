import math

import pytest

from nearest_exit.config import (
    LEGACY_WEIGHT_REFERENCE_MS,
    MAX_PENALTY_MS,
    Config,
    load_config,
    validate_config,
)

PROVIDERS = ["nordvpn", "airvpn", "mullvad", "pia"]


def test_validate_config_reports_common_mistakes():
    cfg = Config()
    cfg.providers.order = ["nordvpn", "bogusvpn"]
    cfg.providers.penalties_ms = {"nordvpn": 0.0, "ghostvpn": 5.0}
    cfg.providers.others_threshold_ms = -1.0
    cfg.defaults.scope = "region"
    cfg.defaults.count = 0
    cfg.geo.lookup = "ipapi"

    warnings = validate_config(cfg, PROVIDERS)

    assert any("providers.order" in w for w in warnings)
    assert any("providers.penalties_ms" in w for w in warnings)
    assert any("others_threshold_ms" in w for w in warnings)
    assert any("defaults.scope" in w for w in warnings)
    assert any("defaults.count" in w for w in warnings)
    assert any("geo.lookup" in w for w in warnings)


def test_validate_config_accepts_defaults():
    assert validate_config(Config(), PROVIDERS) == []


def test_validate_config_rejects_non_finite_penalty():
    cfg = Config()
    cfg.providers.penalties_ms = {"mullvad": math.inf}
    assert any("finite" in w for w in validate_config(cfg, PROVIDERS))


def test_validate_config_flags_preferring_every_provider():
    """Listing everything leaves no 'others', so the threshold does nothing."""
    cfg = Config()
    cfg.providers.order = list(PROVIDERS)
    cfg.providers.others_threshold_ms = 5.0

    assert any("has no effect" in w for w in validate_config(cfg, PROVIDERS))


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


def test_load_config_drops_non_finite_and_invalid_weights(tmp_path):
    cfg = load_config(
        _write(tmp_path, '[providers]\nweights = { mullvad = "inf", pia = -1.0 }\n')
    )

    assert "mullvad" not in cfg.providers.penalties_ms
    assert "pia" not in cfg.providers.penalties_ms
    assert any("finite" in e for e in cfg.load_errors)
    assert any("must be > 0" in e for e in cfg.load_errors)


def test_load_config_clamps_extreme_penalties(tmp_path):
    """An unbounded preference let one provider win regardless of measurement."""
    cfg = load_config(
        _write(tmp_path, "[providers]\npenalties_ms = { nordvpn = 0, pia = 1e9 }\n")
    )

    assert cfg.providers.penalties_ms["pia"] == MAX_PENALTY_MS


def test_clamping_happens_after_anchoring(tmp_path):
    """Clamping first let {-1e9, +1e9} become {-200, +200} and then anchor to a
    400ms spread — twice the stated limit."""
    cfg = load_config(
        _write(tmp_path, "[providers]\npenalties_ms = { nordvpn = -1e9, pia = 1e9 }\n")
    )

    spread = max(cfg.providers.penalties_ms.values())
    assert spread == MAX_PENALTY_MS


def test_penalties_are_normalised_so_the_favourite_costs_nothing(tmp_path):
    cfg = load_config(
        _write(
            tmp_path,
            "[providers]\npenalties_ms = "
            "{ nordvpn = 20, pia = 35, mullvad = 40, airvpn = 25 }\n",
        )
    )

    assert cfg.providers.penalties_ms == {
        "nordvpn": 0.0, "airvpn": 5.0, "pia": 15.0, "mullvad": 20.0,
    }


def test_partial_penalties_are_anchored_against_the_implicit_zero(tmp_path):
    """Providers left out of the table sit at zero, so they are the baseline
    and the listed ones keep their stated cost."""
    cfg = load_config(
        _write(tmp_path, "[providers]\npenalties_ms = { nordvpn = 20, pia = 35 }\n")
    )

    assert cfg.providers.penalties_ms == {
        "mullvad": 0.0, "airvpn": 0.0, "nordvpn": 20.0, "pia": 35.0,
    }


def test_unlisted_providers_are_anchored_too(tmp_path):
    """Anchoring only the listed providers silently changed their relation to
    the unlisted ones, which sit at an implicit zero."""
    cfg = load_config(
        _write(tmp_path, "[providers]\npenalties_ms = { nordvpn = -10 }\n")
    )

    assert cfg.providers.penalties_ms == {
        "nordvpn": 0.0, "mullvad": 10.0, "airvpn": 10.0, "pia": 10.0,
    }


def test_legacy_weights_convert_to_millisecond_penalties(tmp_path):
    """Multiplicative weights scaled with latency, so the same setting meant
    something different on every link. They convert at a fixed reference."""
    cfg = load_config(
        _write(tmp_path, "[providers]\nweights = { nordvpn = 1.0, mullvad = 0.7 }\n")
    )

    expected = round(LEGACY_WEIGHT_REFERENCE_MS * (1 / 0.7 - 1.0), 3)
    assert cfg.providers.penalties_ms["nordvpn"] == 0.0
    assert cfg.providers.penalties_ms["mullvad"] == expected
    assert any("penalties_ms" in e for e in cfg.load_errors)


def test_single_legacy_weight_keeps_its_preference(tmp_path):
    """`weights = { nordvpn = 2.0 }` converted to a single -15ms entry, was
    anchored back to 0, and lost the preference entirely."""
    cfg = load_config(_write(tmp_path, "[providers]\nweights = { nordvpn = 2.0 }\n"))

    penalties = cfg.providers.penalties_ms
    assert penalties["nordvpn"] == 0.0
    assert penalties["mullvad"] == penalties["airvpn"] == penalties["pia"] == 15.0
    # The warning has to quote what was applied, not the pre-anchoring numbers.
    warning = next(e for e in cfg.load_errors if "penalties_ms" in e)
    assert "nordvpn = 0" in warning
    assert "mullvad = 15" in warning


def test_penalties_ms_wins_over_legacy_weights(tmp_path):
    cfg = load_config(
        _write(
            tmp_path,
            "[providers]\n"
            "penalties_ms = { nordvpn = 0, pia = 4 }\n"
            "weights = { nordvpn = 1.0, pia = 0.5 }\n",
        )
    )

    assert cfg.providers.penalties_ms["nordvpn"] == 0.0
    assert cfg.providers.penalties_ms["pia"] == 4.0


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
