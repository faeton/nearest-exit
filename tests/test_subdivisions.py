import importlib
import socket

from nearest_exit.cities import normalize_city
from nearest_exit.geofilter import haversine_km
from nearest_exit.subdivisions import SUBDIVISION_COORDS, subdivision_coords


def test_bare_and_country_tagged_labels_agree():
    bare = subdivision_coords("us", "North Carolina")
    assert bare is not None
    assert subdivision_coords("us", "US North Carolina") == bare
    assert subdivision_coords("US", "us north carolina") == bare
    assert subdivision_coords("us", "  north   carolina  ") == bare


def test_normalization_strips_diacritics_and_case():
    quebec = subdivision_coords("ca", "Quebec")
    assert quebec is not None
    assert subdivision_coords("ca", "Québec") == quebec
    assert subdivision_coords("ca", "CA QUÉBEC") == quebec


def test_only_the_country_tag_is_stripped():
    # "Washington" must not lose its head to a tag that is not the country code.
    assert subdivision_coords("us", "Washington") == SUBDIVISION_COORDS[("us", "Washington")]
    assert subdivision_coords("us", "DE Washington") is None
    # A country tag alone is not a subdivision.
    assert subdivision_coords("us", "US") is None


def test_lookup_is_country_scoped():
    # Ontario is a Canadian province and also a city in California; the country
    # code is what keeps them apart.
    assert subdivision_coords("ca", "Ontario") is not None
    assert subdivision_coords("us", "Ontario") is None


def test_non_places_are_not_mapped():
    # PIA labels these but they are marketing regions, not subdivisions, and
    # "Wilmington" is ambiguous between Delaware and North Carolina.
    for label in ("US East", "US West", "US Streaming Optimized", "US Wilmington"):
        assert subdivision_coords("us", label) is None


def test_missing_inputs_and_unknown_names():
    assert subdivision_coords(None, "Texas") is None
    assert subdivision_coords("us", None) is None
    assert subdivision_coords("  ", "Texas") is None
    assert subdivision_coords("zz", "Texas") is None
    assert subdivision_coords("us", "Atlantis") is None


def test_table_covers_states_and_provinces():
    us = {name for (cc, name) in SUBDIVISION_COORDS if cc == "us"}
    ca = {name for (cc, name) in SUBDIVISION_COORDS if cc == "ca"}
    assert len(us) == 51  # 50 states plus the District of Columbia
    assert len(ca) == 13  # 10 provinces plus 3 territories
    assert "Ontario" in ca and "California" in us


def test_keys_are_already_in_normalized_form():
    # A key that does not survive normalize_city would be unreachable.
    for _cc, name in SUBDIVISION_COORDS:
        assert normalize_city(name) == name.lower()


def test_points_are_population_weighted_not_geographic():
    # The geographic centre of California is ~(37.18, -119.45) in the Sierra
    # foothills; the population-weighted point must be well south of it and
    # much closer to Los Angeles.
    lat, lon = SUBDIVISION_COORDS[("us", "California")]
    assert lat < 36.5
    la = haversine_km(lat, lon, 34.052235, -118.243683)
    geographic_la = haversine_km(37.18, -119.45, 34.052235, -118.243683)
    assert la < geographic_la - 150


def test_module_does_no_network_io(monkeypatch):
    """Import and lookup must work with sockets disabled: the table exists so a
    provider without per-server coordinates needs no second network dependency."""

    def refuse(*args, **kwargs):
        raise AssertionError("subdivisions must not touch the network")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    module = importlib.reload(importlib.import_module("nearest_exit.subdivisions"))
    assert module.subdivision_coords("us", "US Texas") is not None
