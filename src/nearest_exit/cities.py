from __future__ import annotations

import unicodedata

# metadata['geo_precision'] value for relays whose coordinates came from the
# city table below rather than from a country centroid.
from .models import GEO_PRECISION_CITY  # noqa: F401  (re-exported)

# (ISO-2 country code, city) -> (latitude, longitude).
#
# Seeded from Mullvad's public relay location table
# (https://api.mullvad.net/app/v1/relays, 91 cities), which is the only free
# city-level coordinate source among the providers we speak to, then extended
# by hand with the cities AirVPN and PIA serve that Mullvad does not. The data
# is embedded as literals on purpose: providers without per-server coordinates
# must be able to place their relays without a second network dependency.
CITY_COORDS: dict[tuple[str, str], tuple[float, float]] = {
    ("al", "Tirana"): (41.327953, 19.819025),
    ("ar", "Buenos Aires"): (-34.474561, -58.664522),
    ("at", "Vienna"): (48.210033, 16.363449),
    ("au", "Adelaide"): (-34.92123, 138.599503),
    ("au", "Brisbane"): (-27.471, 153.0234),
    ("au", "Melbourne"): (-37.815018, 144.946014),
    ("au", "Perth"): (-31.953512, 115.857048),
    ("au", "Sydney"): (-33.861481, 151.205475),
    ("be", "Brussels"): (50.833333, 4.333333),
    ("bg", "Sofia"): (42.683333, 23.316667),
    ("br", "Fortaleza"): (-3.732714, -38.526997),
    ("br", "Sao Paulo"): (-23.533773, -46.62529),
    ("ca", "Calgary"): (51.037007, -114.058315),
    ("ca", "Montreal"): (45.5053, -73.5525),
    ("ca", "Toronto"): (43.666667, -79.416667),
    ("ca", "Vancouver"): (49.25, -123.133333),
    ("ch", "Zurich"): (47.366667, 8.55),
    ("cl", "Santiago"): (-33.448891, -70.669266),
    ("co", "Bogota"): (4.624335, -74.063644),
    ("cy", "Nicosia"): (35.17025, 33.3587),
    ("cz", "Prague"): (50.083333, 14.466667),
    ("de", "Berlin"): (52.520008, 13.404954),
    ("de", "Dusseldorf"): (51.233334, 6.783333),
    ("de", "Frankfurt"): (50.110924, 8.682127),
    ("dk", "Copenhagen"): (55.666667, 12.583333),
    ("ee", "Tallinn"): (59.436961, 24.753575),
    ("es", "Barcelona"): (41.385063, 2.173404),
    ("es", "Madrid"): (40.408566, -3.69222),
    ("es", "Valencia"): (39.466667, -0.375),
    ("fi", "Helsinki"): (60.192059, 24.945831),
    ("fr", "Bordeaux"): (44.837788, -0.57918),
    ("fr", "Marseille"): (43.29648, 5.38107),
    ("fr", "Paris"): (48.866667, 2.333333),
    ("gb", "Glasgow"): (55.86515, -4.25763),
    ("gb", "London"): (51.514125, -0.093689),
    ("gb", "Manchester"): (53.5, -2.216667),
    ("gr", "Athens"): (37.98381, 23.727539),
    ("hk", "Hong Kong"): (22.283333, 114.15),
    ("hr", "Zagreb"): (45.821, 15.973),
    ("hu", "Budapest"): (47.5, 19.083333),
    ("id", "Jakarta"): (-6.17511, 106.865036),
    ("ie", "Dublin"): (53.35014, -6.266155),
    ("il", "Tel Aviv"): (32.0853, 34.781768),
    ("it", "Milan"): (45.466667, 9.2),
    ("it", "Palermo"): (38.115688, 13.361267),
    ("jp", "Osaka"): (34.672314, 135.484802),
    ("jp", "Tokyo"): (35.685, 139.751389),
    ("mx", "Queretaro"): (20.592774, -100.390225),
    ("my", "Kuala Lumpur"): (3.139003, 101.686852),
    ("ng", "Lagos"): (6.524379, 3.379206),
    ("nl", "Amsterdam"): (52.35, 4.916667),
    ("no", "Oslo"): (59.916667, 10.75),
    ("no", "Stavanger"): (58.964432, 5.72625),
    ("nz", "Auckland"): (-36.848461, 174.763336),
    ("pe", "Lima"): (-12.046373, -77.042755),
    ("ph", "Manila"): (14.599512, 120.984222),
    ("pl", "Warsaw"): (52.25, 21.0),
    ("pt", "Lisbon"): (38.736946, -9.142685),
    ("ro", "Bucharest"): (44.433333, 26.1),
    ("rs", "Belgrade"): (44.787197, 20.457273),
    ("se", "Gothenburg"): (57.70887, 11.97456),
    ("se", "Malmö"): (55.607075, 13.002716),
    ("se", "Stockholm"): (59.3289, 18.0649),
    ("sg", "Singapore"): (1.293056, 103.855833),
    ("si", "Ljubljana"): (46.0569, 14.5057),
    ("sk", "Bratislava"): (48.148598, 17.107748),
    ("th", "Bangkok"): (13.756331, 100.501762),
    ("tr", "Istanbul"): (41.00824, 28.978359),
    ("ua", "Kyiv"): (50.4501, 30.5234),
    ("us", "Ashburn, VA"): (39.043757, -77.487442),
    ("us", "Atlanta, GA"): (33.753746, -84.38633),
    ("us", "Boston, MA"): (42.361145, -71.057083),
    ("us", "Chicago, IL"): (41.881832, -87.623177),
    ("us", "Dallas, TX"): (32.89748, -97.040443),
    ("us", "Denver, CO"): (39.739236, -104.990251),
    ("us", "Detroit, MI"): (42.331389, -83.045833),
    ("us", "Houston, TX"): (29.749907, -95.358421),
    ("us", "Kansas City, MO"): (39.099789, -94.57856),
    ("us", "Los Angeles, CA"): (34.052235, -118.243683),
    ("us", "McAllen, TX"): (26.203407, -98.230011),
    ("us", "Miami, FL"): (25.761681, -80.191788),
    ("us", "New York, NY"): (40.73061, -73.935242),
    ("us", "Phoenix, AZ"): (33.448376, -112.074036),
    ("us", "Raleigh, NC"): (35.787743, -78.644257),
    ("us", "Salt Lake City, UT"): (40.758701, -111.876183),
    ("us", "San Francisco, CA"): (37.723459, -122.397957),
    ("us", "San Jose, CA"): (37.338208, -121.886329),
    ("us", "Seattle, WA"): (47.608013, -122.335167),
    ("us", "Secaucus, NJ"): (40.789543, -74.0565),
    ("us", "Washington DC"): (38.889484, -77.035278),
    ("za", "Johannesburg"): (-26.195246, 28.034088),
    # Beyond Mullvad: cities AirVPN and PIA serve, plus the spellings those
    # two use for a city Mullvad names differently.
    ("gb", "Southampton"): (50.909698, -1.404351),
    ("it", "Milano"): (45.466667, 9.2),
    ("lv", "Riga"): (56.94965, 24.105186),
    ("nl", "Alblasserdam"): (51.866667, 4.666667),
    ("se", "Uppsala"): (59.858562, 17.638927),
    ("tw", "Taipei"): (25.032969, 121.565418),
    ("us", "Baltimore, MD"): (39.290385, -76.612189),
    ("us", "Fremont, CA"): (37.548271, -121.988571),
    ("us", "Honolulu, HI"): (21.306944, -157.858337),
    ("us", "Las Vegas, NV"): (36.169941, -115.13983),
    ("us", "New York City"): (40.73061, -73.935242),
    ("us", "Silicon Valley"): (37.354108, -121.955238),
}


def normalize_city(name: str) -> str:
    """Fold a provider's city label to the table's key form: diacritics
    dropped, case folded, whitespace collapsed. Providers spell the same city
    in different scripts and spacings ("Malmö" / "malmo ")."""
    decomposed = unicodedata.normalize("NFKD", name)
    plain = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return " ".join(plain.lower().split())


def _build_index() -> dict[tuple[str, str], tuple[float, float]]:
    """Index each city under its full name and, for "City, Region" labels,
    under the bare city too, so "Ashburn, VA" also answers to "ashburn"."""
    index: dict[tuple[str, str], tuple[float, float]] = {}
    for (cc, city), coords in CITY_COORDS.items():
        key = cc.lower()
        index.setdefault((key, normalize_city(city)), coords)
        head, sep, _rest = city.partition(",")
        if sep:
            index.setdefault((key, normalize_city(head)), coords)
    return index


def _build_names() -> dict[tuple[str, str], str]:
    """The same keys as `_build_index`, mapped to the table's own spelling.

    A provider whose label hides the city ("Netherlands" for nl_amsterdam)
    can recover a presentable name from its id slug without inventing casing:
    `.title()` would render "new york city" correctly but mangle anything the
    table spells deliberately.
    """
    names: dict[tuple[str, str], str] = {}
    for (cc, city), _coords in CITY_COORDS.items():
        key = cc.lower()
        names.setdefault((key, normalize_city(city)), city)
        head, sep, _rest = city.partition(",")
        if sep:
            names.setdefault((key, normalize_city(head)), head)
    return names


_INDEX = _build_index()
_NAMES = _build_names()


def city_display_name(country_code: str | None, city: str | None) -> str | None:
    """The table's spelling of a city, given any label that resolves to it."""
    if not country_code or not city:
        return None
    cc = country_code.strip().lower()
    if not cc:
        return None
    return _NAMES.get((cc, normalize_city(city)))


def city_coords(country_code: str | None, city: str | None) -> tuple[float, float] | None:
    """Exact coordinates for a provider's (country, city) pair, or None.

    The city half is matched on the full label first and then on the part
    before a comma, because providers qualify cities inconsistently
    ("Toronto, Ontario" here, "Toronto" there)."""
    if not country_code or not city:
        return None
    cc = country_code.strip().lower()
    if not cc:
        return None
    name = normalize_city(city)
    hit = _INDEX.get((cc, name))
    if hit is not None:
        return hit
    head, sep, _rest = name.partition(",")
    if sep:
        return _INDEX.get((cc, head.strip()))
    return None
