# Provider notes

Per-provider facts about the endpoints Nearest Exit reads: what they return,
what they do not, and the things a maintainer would otherwise rediscover the
hard way. Everything here was verified against the live APIs while fixing the
adapters; the counts are from those runs and will drift as fleets change.

All four endpoints are unauthenticated and free. All responses are cached under
`~/.cache/nearest-exit/` with a 24-hour TTL; writes go through a temp file and
`os.replace`, and an unparsable entry reads as a cache miss rather than
wedging the tool.

## Coordinates: nobody publishes them per relay

Only **NordVPN** returns coordinates at all, and they are city coordinates
wearing a per-server field (see the note under the table below). Mullvad,
AirVPN and PIA publish a country code and a city-ish label and nothing else,
so for those three the position comes from `src/nearest_exit/cities.py`,
an embedded table
of 103 `(country_code, city) → (lat, lon)` entries. The table is embedded as
literals on purpose: a provider without coordinates must be placeable without a
second network dependency.

The table was seeded from Mullvad's own free, unauthenticated
`https://api.mullvad.net/app/v1/relays` location list (91 cities) and extended
by hand with the cities AirVPN and PIA serve that Mullvad does not. Lookup
folds case, collapses whitespace and strips diacritics, and indexes each
`"City, Region"` entry under the bare city too — which is what makes AirVPN's
`"Toronto, Ontario"` resolve against Mullvad's `"Toronto"` and Mullvad's
`"Atlanta, GA"` resolve against a plain `"Atlanta"`.

Coverage measured against the live payloads:

| provider | relays / regions | city precision | country precision |
|----------|------------------|----------------|-------------------|
| Mullvad  | 587 relays       | 587 (100%)     | 0                 |
| AirVPN   | 257 relays       | 257 (100%)     | 0                 |
| PIA      | 189 regions      | 39 (21%)       | 150               |
| NordVPN  | 8660 servers     | 8660 (100%)    | 0                 |

No provider reaches better than city precision. NordVPN is the only one that
returns coordinates at all, and they are per-city rather than per-machine: 800
sampled servers across 30 cities carry exactly one coordinate each, and its
London and Paris values are byte-identical to Mullvad's independently
published city table. So NordVPN's relays are labelled `"city"` like everyone
else's, with a country-centroid fallback for any server that arrives without
coordinates.

Where a city cannot be resolved, the relay falls back to a country centroid
(113 embedded entries) and records `metadata["geo_precision"] = "country"`.
Mean displacement from country centroid to the true city coordinate was 645km
for AirVPN (max 2190km) and 1101km for PIA (max 6056km) — that is the ranking
error the city table removes, and the reason a country-precision relay carries
a 750km uncertainty penalty in `top_k_by_distance`.

Country-derived coordinates never feed back into `centroids_from_relays`, which
would otherwise make the centroid table self-referential rather than an
observation of where relays actually are.

## The OpenVPN control channel, per provider

`--probe openvpn` sends a 14-byte plaintext `P_CONTROL_HARD_RESET_CLIENT_V2`
and times the response. What counts as a response differs by provider, and it
is worth knowing which you are getting:

| provider | transport | port | behaviour |
|---|---|---|---|
| PIA | UDP | 8080, 853 | answers with `HARD_RESET_SERVER_V2` |
| AirVPN | TCP | 443 | `tls-auth`: reads it, fails the HMAC, closes |
| NordVPN | TCP | 443 | `tls-auth`: same |
| Mullvad | — | — | no OpenVPN fleet; no target exists |

Both behaviours are a round trip through the daemon, which is the point. The
TCP close is not a network artifact: connecting and sending *nothing* holds the
connection open for at least six seconds, and sending the reset closes it one
RTT later, so the close is caused by the daemon reading the packet.

PIA advertises `openvpn_udp` on 8080, 853, 123 and 53. **Do not use 123 or
53** — they are routinely intercepted on the way out by local NTP and DNS
middleboxes, so they measure the middlebox rather than the relay.

## IKEv2, per provider

`--probe ikev2` sends a 216-byte `IKE_SA_INIT` proposing only DH group 1 and
times the `NO_PROPOSAL_CHOSEN` refusal.

| provider | IKEv2 fleet | probed? |
|---|---|---|
| NordVPN | 4302 of ~6000 servers, 125 countries | **yes**, UDP/500 |
| PIA | all 189 regions publish an `ikev2` service | **no** — see below |
| AirVPN | none | no |
| Mullvad | none | no |

**PIA answers, and is still excluded.** In one session its IKE listener was
unreliable exactly where its OpenVPN listener was not. Head to head on four of
the regions that missed a fleet sweep, three packets each — one session, one
uplink, and the timeout was 3s so "silent" and "slower than 3s" are not
separable here:

```text
region          ovpnudp/8080 3x      ike/500 3x
al                 3/3  158.3ms      3/3   160.1ms
hk                 3/3  255.2ms      0/3   silent
macau              3/3  303.4ms      1/3  2291.0ms     <-- 2.3 seconds
mongolia           3/3  317.4ms      1/3   318.0ms
```

Only `macau` produced a multi-second sample; `mongolia` was lossy at a normal
latency, and `al` was fine. But a 2.3-second sample landing in a latency
ranking is a fabricated answer that looks like a measurement, and PIA's
OpenVPN listener did not falter on any of these under the same load in the
same run. Excluding IKE for PIA is therefore the conservative call rather than
a proven necessity — PIA already has a probe that worked.

**NordVPN's IKEv2 reached relays ICMP could not, from here.** One server per
country, one scan, one residential uplink: ICMP answered 50 of 125, IKE
answered 125 of 125, and the 75 IKE-only hosts were 75 distinct IPs (IN, TH,
VN, PK, EG, KE, MA, KZ and 67 more). Sample uniformly at random instead and
the gain collapses to ~5%, because a random draw is dominated by the big
European fleets, which answer ping.

Treat the 125/50 split as a statement about this path rather than about
NordVPN: whether a relay answers ICMP depends on the route and on whatever
filters sit along it, and the same measurement from a datacentre would likely
look different. What survives re-measurement is the shape of the finding — the
gain lives in the small virtual locations, which is where a user asking for an
exit in Nepal has exactly one candidate.

## Mullvad

**Endpoint:** `https://api.mullvad.net/www/relays/all/` — a JSON array, no
parameters, one object per server.

**Fields it actually returns**, verified as the live key union: `active`,
`city_code`, `city_name`, `country_code`, `country_name`, `daita`, `fqdn`,
`hostname`, `ipv4_addr_in`, `ipv4_v2ray`, `ipv6_addr_in`, `multihop_port`,
`network_port_speed`, `owned`, `provider`, `pubkey`, `socks_name`,
`socks_port`, `ssh_fingerprint_*`, `status_messages`, `stboot`, `type`.

**It does not return `latitude` or `longitude`.** This is worth stating loudly
because the repository's own test fixture used to carry those fields, so
`normalize()`'s `h.get("latitude")` looked correct while returning `None` in
production for every relay Mullvad has ever published. Coordinate-based
selection was silently alphabetical for Mullvad — relays without coordinates
sort under `(1, inf, hostname)` — and the fixture was the only thing hiding it.
The fixture is now a verbatim four-relay capture. If you add a fixture, capture
it; do not write it.

**Coordinates** come from the embedded city table keyed on `(country_code,
city_name)`. Since that table was seeded from Mullvad's own location list, it
covers Mullvad exactly: all 587 live relays resolve at city precision,
comma-qualified names like `"Atlanta, GA"` included.

**SOCKS5: published, but not for us.** 574 of 587 relays carry `socks_name`
and `socks_port`, which is exactly the shape `targets.socks5_target` wants.
They are deliberately *not* normalised, because every one of those names
resolves into `10.124.0.0/16` — 12 sampled at random, 12 RFC1918. Mullvad's
proxies are reachable only from inside a Mullvad tunnel, which is the state
this tool runs before. Normalising them produced an unreachable target on
every relay and a `socks5` tag that made `--protocol socks5` select relays it
could never measure, reporting the timeout as though the relay were slow.
`providers/mullvad.py::_socks5_target` is kept as a function that returns
`None` so the reason stays next to the fields.

**Bridges are not exits.** `type` is the first entry in `protocols` and can be
`wireguard`, `openvpn` or `bridge`. A bridge is entry obfuscation and cannot
carry exit traffic; ranking one is a category error, not a close call about
quality. A live run recommended `ca-mtr-br-001` as the fourth-best exit before
`filter_relays` was tightened to require wireguard, openvpn or ikev2 unless a
protocol was named explicitly.

**No load figure.** `Relay.load` is `None` for every Mullvad relay, so the load
term of the effective cost is always zero here. `active` and `owned` come
straight from the API. The relay id is the hostname.

## NordVPN

**Endpoints:**

- `https://api.nordvpn.com/v1/servers` — the raw inventory. This is the
  candidate source.
- `https://api.nordvpn.com/v1/servers/recommendations` — NordVPN's own ranking
  of its own fleet. Fallback only.
- `https://api.nordvpn.com/v1/servers/countries` — maps an ISO country code to
  the numeric `country_id` the other endpoints filter on.

**Why the inventory and not recommendations.** The tool's premise is that it
does not trust the provider's ranking. Sourcing candidates from
`/recommendations?limit=50` meant re-ordering a shortlist NordVPN had already
chosen and never seeing a server NordVPN declined to recommend. The object
shape of the two endpoints is identical key-for-key, so switching needed no
field changes. Recommendations remain as a fallback when the inventory fetch
fails, and a degraded run warns on stderr naming the endpoint and the cause;
every relay also carries the source in `metadata["_nearest_exit_source"]`.

**`limit=0` means no limit** and returns the whole inventory, about 8832
servers.

**Sparse fieldsets work, but only in one spelling.** This is the single most
expensive thing to rediscover:

```text
fields[]=id&fields[]=hostname                 -> HTTP 400
                                                 {"errors":{"message":"Invalid request",
                                                            "code":200138}}
fields[servers.id]&fields[servers.hostname]   -> HTTP 200
```

The dotted-key form — the form NordVPN's own Linux client uses — is honoured,
nested paths included. On the wire that is **33,355,923 bytes in 4.46s down to
4,597,952 bytes in 1.28s** for the full inventory, and normalized output from
the fielded response is identical to normalized output from the raw one across
all 8832 servers.

**Unknown field paths are dropped silently rather than erroring**, so
`INVENTORY_FIELDS` is the contract: anything `normalize()` or `spread()` reads
must be listed there or it arrives as `None`, with no warning of any kind.
Currently 13 paths are requested. Note that `station` is populated for every
inventory server, so the `ips[]` fallback in `normalize()` — which only the
recommendations payload needs — is deliberately not requested.

**What `fields` cannot do.** It selects keys, not values, and
`filters[servers_technologies][identifier]` selects *servers* rather than
pruning their technologies array. Servers advertise around eight technologies
each and only four map to something usable, so a small client-side
`prune_inventory()` remains; it saves roughly 1.2MB of cache and relay
metadata.

**Relays that cannot be exits.** About 170 of 8832 servers advertise only
`socks` or `openvpn_xor_*` and map to no protocol this tool can use as an exit.
They are dropped by `prune_inventory()`. This is a filter on what a server
*can do*, never on how good NordVPN says it is — the distinction matters,
because hostname ordering sorts `socks-us71` ahead of `us2943` and SOCKS-only
relays would otherwise crowd out the candidate set.

**Technologies mapped:** `wireguard_udp` → wireguard, `openvpn_udp` /
`openvpn_tcp` → openvpn, `ikev2` → ikev2. The raw inventory also exposes
`nordwhisper`, `proxy_ssl` and obfuscated / dedicated-IP variants, which are
preserved in metadata but not treated as protocols.

**No SOCKS5.** The inventory exposes openvpn, wireguard, ikev2, nordwhisper and
proxy_ssl, but no SOCKS technology on any of the 300 servers sampled. There is
nothing to normalise, so `--protocol socks5` finds no NordVPN relays by design.

**Candidate ordering is deliberately neutral.** `spread()` round-robins over
`(country, city)` buckets, because the inventory comes back ordered by server
id — which clusters by country — so a plain head of 50 would return roughly one
country. `limit=50` covers 33 countries and `limit=500` covers 149. Within a
bucket the order is hostname then id, and explicitly *not* load: sorting by
NordVPN's reported load would make the least-loaded box in each city the only
one that ever gets probed, which is the provider deciding who gets measured and
self-fulfilling besides. After the fix, `ch-onion2.nordvpn.com` at load 95 is
reachable as a candidate. `load` still reaches `Relay.load` and is used as a
small tiebreaker *after* the measurements are in.

**The inventory cache key deliberately omits `limit`**, so the three limits the
CLI uses (50, 500, 30) share one fetch instead of three. It is keyed on
`(country_id, technology)` and versioned (`nordvpn-inventory-v3`) so caches in
an earlier shape are not read back as if they were this one.

**Coordinates:** `locations[].latitude` / `longitude`, requested through the
sparse fieldset. These are city-level, not per-machine — in the captured
fixture, London is `(51.514125, -0.093689)` and Paris is `(48.866667,
2.333333)`, byte-identical to Mullvad's published coordinates for those cities.
NordVPN relays do not get a `geo_precision` marker, so they are treated as
having a known position and carry no distance penalty.

`active` is `status == "online"`. The relay id is the numeric server id as a
string, which is why merging and history are keyed on `(provider, id)`: a bare
numeric id collides with nothing in NordVPN and everything elsewhere.

## AirVPN

**Endpoint:** `https://airvpn.org/api/status/?format=json`, sent with an
explicit `User-Agent`. AirVPN documents `status` as a free API service; the
docs mention a rate limit of 600 requests per 10 minutes, which the 24-hour
cache keeps us far away from.

**Fields it returns**, verified as the key union across servers: `bw`,
`bw_max`, `continent`, `country_code`, `country_name`, `currentload`, `health`,
`ip_v4_in1`..`ip_v4_in4`, `ip_v6_in1`..`ip_v6_in4`, `location`, `public_name`,
`users`, `warning`.

**No coordinates.** `location` is a free-text city name, not a position. All
257 relays nonetheless resolve at city precision through the embedded table.

**Up to four IPv4 entry addresses per logical server** (`ip_v4_in1..4`, and the
same for IPv6). The first is the canonical `Relay.ipv4`; all of them are kept
in `metadata["entry_ipv4_all"]` and probed **concurrently**. Probing them
serially cost four `ping` runs per relay — around twelve seconds each on macOS,
where ping's default interval is one second — for the entire AirVPN fleet.

**Health is a gate, not a penalty.** `active` is `health == "ok"`, so a relay
reporting anything else is marked inactive and excluded unless
`--include-inactive` is passed. `currentload` becomes `Relay.load`.

**Protocols are assumed, not reported.** The status API says nothing about
per-server protocol support, so every AirVPN relay is normalised as
`("openvpn", "wireguard")` on the basis that AirVPN supports both fleet-wide.
If that stops being true, this is where it breaks.

**No SOCKS endpoints** in the status API. The relay id is `public_name`, and
servers with no IPv4 entry address at all are skipped.

## Private Internet Access

**Endpoint:** `https://serverlist.piaservers.net/vpninfo/servers/v6`, sent with
an explicit `User-Agent`.

**The response is not pure JSON.** It is one JSON object, then a newline, then
a base64 signature block. Feeding the whole body to `json.loads` fails.
`json.JSONDecoder().raw_decode()` consumes the first JSON value and ignores the
tail, which is the correct handling — the signature is not corruption and
should not be treated as a parse error. Verifying it is a possible future
addition; stripping it is mandatory today.

**Region fields:** `auto_region`, `country`, `dns`, `geo`, `id`, `name`,
`offline`, `port_forward`, `servers`. **`geo` is a boolean** — a virtual-location
flag — and not a position. There are no coordinates anywhere in the payload.

**One relay per region, not per server.** The canonical probe IP is the
region's first available endpoint in the order wg, ovpnudp, ovpntcp, socks5.
All per-protocol server lists are preserved under `metadata["servers"]`, and
the port table under `metadata["groups"]` — the ports live at the top level of
the payload, not on the region.

**Protocol groups mapped:** `wg` → wireguard, `ovpnudp` / `ovpntcp` → openvpn,
`socks5` → socks5. `meta` is a control endpoint, not a tunnel, so it is
excluded from `protocols` — but it is the TCP fallback target for PIA relays,
because a connect to a service PIA actually runs beats a blind connect to 443.

**SOCKS5 is available**, at `servers.socks5[0].ip` with the port from
`groups.socks5[0].ports`.

**Region labels need two tricks to resolve to a city**, and even then only 39
of 189 regions do:

1. Region names carry a country tag: `"DE Berlin"` is Berlin, and `"UK London"`
   is London even though the country code is `GB` — PIA labels its British
   regions "UK".
2. Several single-city regions are labelled with the *country* while the id
   names the city: `"Netherlands"` is `nl_amsterdam`, `"Bulgaria"` is `sofia`.
   So the label is tried first and the id slug second, with `-pf` / `-so`
   suffixes stripped and a leading country token removed.

A label only counts if it hits the table exactly. `"US East"`, `"US Texas"` and
the `"… Streaming Optimized"` duplicates therefore fall through to the country
centroid rather than being assigned an invented position — which is the right
outcome, since none of them names a city. `us-wilmington` is deliberately left
at country precision too: Wilmington DE and Wilmington NC are 600km apart and
the payload does not say which one it is.

**No load figure.** `offline` maps to `active = False`; `port_forward` and
`geo` are preserved in metadata. The relay id is the region id.
