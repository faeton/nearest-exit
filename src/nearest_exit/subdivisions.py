"""First-level subdivision coordinates, for providers that label a region by
state or province instead of by city.

The points are **population-weighted centres, not geographic ones**. A
datacentre follows population and peering, not land area: the geographic centre
of California is in the Sierra foothills, while its capacity is all in Los
Angeles and the Bay Area. The population-weighted point sits in the southern
Central Valley — several hundred kilometres closer to where a region labelled
"US California" actually terminates.

Sources:
  us  Census Bureau, "Centers of Population by State: 2020"
      (www2.census.gov/geo/docs/reference/cenpop2020/CenPop2020_Mean_ST.txt),
      which is the population-weighted mean centre by definition. 50 states
      plus DC; territories are omitted because they carry their own ISO code.
  ca  Statistics Canada publishes no per-province equivalent, so each province
      is the population-weighted mean of its 2021 Census metropolitan areas and
      larger agglomerations, each placed at its core city. Ontario lands at
      (43.81, -79.41), i.e. just north of Toronto, which is where every
      Canadian transit route actually is.

Literals only, like cities.py: a provider that ships no per-server coordinates
must be able to place its relays without a second network dependency, so
nothing here touches the network at import or at call time.
"""

from __future__ import annotations

from .cities import normalize_city

# (ISO-2 country code, subdivision name) -> (latitude, longitude).
SUBDIVISION_COORDS: dict[tuple[str, str], tuple[float, float]] = {
    ("us", "Alabama"): (33.016191, -86.753353),
    ("us", "Alaska"): (61.408891, -148.961508),
    ("us", "Arizona"): (33.371388, -111.882468),
    ("us", "Arkansas"): (35.199251, -92.713212),
    ("us", "California"): (35.491035, -119.347852),
    ("us", "Colorado"): (39.534747, -105.185361),
    ("us", "Connecticut"): (41.492835, -72.878714),
    ("us", "Delaware"): (39.333614, -75.547709),
    ("us", "District of Columbia"): (38.910168, -77.013993),
    ("us", "Florida"): (27.839295, -81.636016),
    ("us", "Georgia"): (33.410677, -83.891248),
    ("us", "Hawaii"): (21.112376, -157.485304),
    ("us", "Idaho"): (44.220476, -115.224610),
    ("us", "Illinois"): (41.312077, -88.372974),
    ("us", "Indiana"): (40.144178, -86.251589),
    ("us", "Iowa"): (41.936630, -93.037218),
    ("us", "Kansas"): (38.480984, -96.409286),
    ("us", "Kentucky"): (37.838308, -85.261296),
    ("us", "Louisiana"): (30.696198, -91.474266),
    ("us", "Maine"): (44.267404, -69.764596),
    ("us", "Maryland"): (39.136636, -76.802227),
    ("us", "Massachusetts"): (42.273659, -71.350366),
    ("us", "Michigan"): (42.864675, -84.213172),
    ("us", "Minnesota"): (45.189990, -93.558751),
    ("us", "Mississippi"): (32.575361, -89.566275),
    ("us", "Missouri"): (38.432921, -92.234929),
    ("us", "Montana"): (46.760509, -111.318567),
    ("us", "Nebraska"): (41.167883, -97.222143),
    ("us", "Nevada"): (37.015907, -116.173753),
    ("us", "New Hampshire"): (43.149147, -71.455608),
    ("us", "New Jersey"): (40.438248, -74.424465),
    ("us", "New Mexico"): (34.607808, -106.332167),
    ("us", "New York"): (41.471783, -74.590827),
    ("us", "North Carolina"): (35.538715, -79.675021),
    ("us", "North Dakota"): (47.339540, -99.444952),
    ("us", "Ohio"): (40.438553, -82.796902),
    ("us", "Oklahoma"): (35.606866, -96.854171),
    ("us", "Oregon"): (44.753509, -122.588257),
    ("us", "Pennsylvania"): (40.443486, -76.965232),
    ("us", "Rhode Island"): (41.755677, -71.450484),
    ("us", "South Carolina"): (34.022471, -80.996482),
    ("us", "South Dakota"): (43.986511, -98.922285),
    ("us", "Tennessee"): (35.821189, -86.332487),
    ("us", "Texas"): (30.909581, -97.328656),
    ("us", "Utah"): (40.385835, -111.948021),
    ("us", "Vermont"): (44.101952, -72.824240),
    ("us", "Virginia"): (37.850195, -77.765608),
    ("us", "Washington"): (47.329504, -121.632620),
    ("us", "West Virginia"): (38.823276, -80.671314),
    ("us", "Wisconsin"): (43.723662, -89.031445),
    ("us", "Wyoming"): (42.694801, -106.984779),
    ("ca", "Alberta"): (52.166049, -113.752465),
    ("ca", "British Columbia"): (49.364688, -122.822770),
    ("ca", "Manitoba"): (49.892246, -97.309978),
    ("ca", "New Brunswick"): (45.785816, -65.711256),
    ("ca", "Newfoundland and Labrador"): (47.732010, -53.356085),
    ("ca", "Northwest Territories"): (62.454000, -114.371800),
    ("ca", "Nova Scotia"): (44.896475, -63.012408),
    ("ca", "Nunavut"): (63.746700, -68.517000),
    ("ca", "Ontario"): (43.806686, -79.411583),
    ("ca", "Prince Edward Island"): (46.266734, -63.250917),
    ("ca", "Quebec"): (45.776504, -73.234046),
    ("ca", "Saskatchewan"): (51.390873, -105.767961),
    ("ca", "Yukon"): (60.721200, -135.056800),
}

_INDEX: dict[tuple[str, str], tuple[float, float]] = {
    (cc.lower(), normalize_city(name)): coords
    for (cc, name), coords in SUBDIVISION_COORDS.items()
}


def subdivision_coords(country_code: str | None, label: str | None) -> tuple[float, float] | None:
    """Coordinates for a provider's (country, subdivision) pair, or None.

    The label is matched whole first and then with a leading country tag
    removed, because providers qualify subdivisions inconsistently ("US Texas"
    here, "Texas" there). Only a tag equal to the country code is stripped, so
    a subdivision whose own name starts with a word cannot lose it.
    """
    if not country_code or not label:
        return None
    cc = country_code.strip().lower()
    if not cc:
        return None
    name = normalize_city(label)
    hit = _INDEX.get((cc, name))
    if hit is not None:
        return hit
    tag, sep, rest = name.partition(" ")
    if sep and rest and tag == cc:
        return _INDEX.get((cc, rest))
    return None
