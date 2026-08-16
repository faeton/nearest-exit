import ast
import importlib
import socket
from pathlib import Path

from nearest_exit import cities
from nearest_exit.cities import CITY_COORDS, GEO_PRECISION_CITY, city_coords, normalize_city

SOURCE = Path(cities.__file__).read_text()


def test_table_is_offline_data():
    """The table is embedded literals; importing it must not open a socket."""
    tree = ast.parse(SOURCE)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            imported.add(node.module.split(".")[0])
    # Relative imports stay inside this package; the reload test below proves
    # nothing in that chain opens a socket either.
    assert imported <= {"__future__", "unicodedata"}


def test_reimport_without_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("cities must not touch the network")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    module = importlib.reload(cities)
    assert module.city_coords("se", "Stockholm") is not None


def test_geo_precision_constant():
    assert GEO_PRECISION_CITY == "city"


def test_table_entries_are_plausible():
    for (cc, city), (lat, lon) in CITY_COORDS.items():
        assert len(cc) == 2 and cc.islower(), (cc, city)
        assert city.strip() == city and city
        assert -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0, (cc, city)


def test_normalize_city_folds_case_space_and_diacritics():
    assert normalize_city("  Kuala   Lumpur ") == "kuala lumpur"
    assert normalize_city("Malmö") == "malmo"
    assert normalize_city("SÃO PAULO") == "sao paulo"


def test_lookup_is_case_and_whitespace_insensitive():
    expected = city_coords("se", "Stockholm")
    assert expected is not None
    assert city_coords("SE", "  STOCKHOLM  ") == expected
    assert city_coords(" se ", "Stockholm") == expected
    assert city_coords("my", "Kuala\t Lumpur") == city_coords("my", "Kuala Lumpur")


def test_lookup_ignores_diacritics():
    assert city_coords("se", "Malmö") == city_coords("se", "Malmo")
    assert city_coords("br", "São Paulo") == city_coords("br", "Sao Paulo")


def test_comma_forms_resolve_both_ways():
    ashburn = city_coords("us", "Ashburn, VA")
    assert ashburn is not None
    # Table side: the bare city is indexed too.
    assert city_coords("us", "ashburn") == ashburn
    # Query side: a differently-qualified label falls back to its head.
    assert city_coords("us", "Atlanta, Georgia") == city_coords("us", "Atlanta, GA")
    assert city_coords("ca", "Toronto, Ontario") == city_coords("ca", "Toronto")


def test_provider_specific_spellings():
    assert city_coords("it", "Milano") == city_coords("it", "Milan")
    assert city_coords("us", "New York City") == city_coords("us", "New York")
    for cc, city in (("lv", "Riga"), ("tw", "Taipei"), ("nl", "Alblasserdam")):
        assert city_coords(cc, city) is not None, (cc, city)


def test_unknown_inputs_return_none():
    assert city_coords("us", "Nowhereville") is None
    assert city_coords("zz", "Stockholm") is None
    assert city_coords(None, "Stockholm") is None
    assert city_coords("se", None) is None
    assert city_coords("", "") is None
    assert city_coords("se", "   ") is None
    # A real city, but paired with the wrong country.
    assert city_coords("de", "Stockholm") is None
