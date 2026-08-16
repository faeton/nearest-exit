# Research log

Historical notes. This file is the survey work that shaped Nearest Exit,
extracted from `PLAN.md` so that the plan can be a plan.

**Read this as a record, not as a specification.** The verifications below are
dated and were made from one machine on one network; several have since been
superseded by the live checks recorded in `docs/provider-notes.md`, which is
the authority on what the endpoints actually do today. Where the two disagree,
provider-notes wins. Nothing here is a commitment to build anything.

---

## Prior art surveyed

### `z3d6380/nordPing`

Probes numeric NordVPN hostname ranges (`us9000`..`us9500`) directly.

Useful idea: hostname-range probing can find reachable NordVPN hosts with no
metadata source at all. Rejected as a primary design: it guesses ranges, misses
servers outside them, has no city or load awareness, spends time on nonexistent
hosts, builds shell strings, and can fail on no-response output. Kept only as a
theoretical last-resort fallback, and never implemented.

### `mrzool/nordvpn-server-find`

Shell script over `https://nordvpn.com/api/server/stats` for load data, with
country filtering, a max-load threshold, and a quiet mode that prints only the
best hostname. Previously used
`https://nordvpn.com/wp-admin/admin-ajax.php?action=servers_recommendations`.

Taken: a quiet/scripting mode that prints a bare hostname; country-code
validation with friendly errors; stripping colour when stdout is not a TTY.

Rejected: the WordPress admin-ajax endpoint (returned a Cloudflare browser
challenge from this environment on 2026-05-01); `jq` as a runtime dependency;
ranking by provider-reported load.

### `trishmapow/nordvpn-tools`

Python, maps country code to id via `/v1/servers/countries`, then reads
`/v1/servers/recommendations`, filters by city and max load, optionally runs
`fping` on Linux.

Taken: the country-id mapping step (still in use); requesting only the fields
needed; city filters; keeping fixtures so normalization is testable.

Rejected: `fping` as a core requirement; a third-party table library; and —
after the audit — recommendations as the candidate source at all.

Dated verification: `/v1/servers/recommendations?limit=1` returned rich JSON
from this environment on 2026-05-01, including `hostname`, `station`, `load`,
`status`, `locations`, `services`, `technologies`, `groups` and WireGuard
public-key metadata.

### `malgr/NordVPN-Server-Lister`

Calls `https://api.nordvpn.com/server`; filters by country, max load, and
proxy/SOCKS flags.

Dated verification: that endpoint returned HTTP 403 from this environment on
2026-05-01. Treat it as historical.

Taken: the idea of a normalized feature model instead of provider-specific
boolean soup.

### `openpyn-nordvpn`

A full NordVPN OpenVPN manager: caches NordVPN JSON, filters by country, area,
P2P, dedicated IP, double VPN, Onion-over-VPN, obfuscation and protocol, then
connects and manages firewall and DNS.

Taken: capability filters beyond country and city; caching with graceful
fallback to a stale entry; the "feature profile" idea.

Rejected: streaming-service-specific hardcoded server ranges; becoming a
connection manager; mixing firewall, DNS and ranking logic; and its rule that
skips servers with reported load below 6 (see "Cut" in `PLAN.md`).

### `grant0417/mullvad-ping`

Deno CLI over the Mullvad relay API. Lists countries, cities, providers and
servers; filters by country, city code, type, port speed, provider, ownership,
run mode and inactive status; parses min/avg/max/mdev from ping output.

Taken: `list` subcommands as a debugging surface; preserving jitter rather than
only an average; JSON output containing full normalized metadata plus probe
metrics.

Rejected: serial pinging on the main scan path.

### `ip-address-list/nordvpn`

Publishes refreshed NordVPN HTTPS proxy IP lists.

Taken: if a third-party list is ever used, its origin must be labelled in the
output and it must not be mixed silently with official data.

### Gluetun

Not a pinger, but a mature cross-provider server model covering AirVPN, IVPN,
Mullvad, NordVPN, PIA, ProtonVPN, Surfshark and Windscribe, with fields for
protocol, country, region, city, ISP, hostname, categories, TCP/UDP support,
WireGuard public key, ownership, tier, streaming, multihop, port forwarding,
secure core, Tor and IPs.

Taken: a broad normalized server model from the start even if V1 fills a
subset; separating provider update code from provider selection code.

Rejected: Gluetun's connection-management scope.

---

## Provider research (Tier 2 and 3)

Providers not implemented. Priority follows how public, structured and stable
the metadata is.

### ExpressVPN

Publishes a public location and protocol availability matrix
(`https://www.expressvpn.com/vpn-server`) but no unauthenticated per-server IP
list; manual configuration requires signing in, after which users can download
`.ovpn` files. Likely adapter modes, in order of plausibility: import
user-downloaded `.ovpn` files and probe the `remote` targets; read the public
location list for availability only. Never scrape the authenticated account
page, and never ask for credentials. Lightway can be metadata; probing it is
out of scope absent a safe public handshake.

### Proton VPN

Publicly documents server locations and counts
(`https://protonvpn.com/vpn-servers`). A full unauthenticated per-server list
may be intentionally unavailable; needs research before an adapter is worth
starting.

### IVPN, Surfshark, Windscribe, Perfect Privacy

All supported by Gluetun, which implies a machine-readable source exists. For
each, the open question is the same: is there an unauthenticated endpoint that
exposes per-server IPs and protocol ports, or only location-level names?
Perfect Privacy is additionally interesting because it publishes detailed
server status.

### Tier 3

CyberGhost, IPVanish, PrivadoVPN, PrivateVPN, PureVPN, TorGuard, VyprVPN, VPN
Unlimited. Lower priority: server data is less structured, some require
authenticated config downloads, some publish only country lists, and some use
rotating DNS names behind load balancers. Reachable in principle through a
user-supplied hostname or config import.

### VPN Gate

`https://www.vpngate.net/api/iphone/` returns a public CSV of volunteer-run
servers with country, coordinates, sessions — and with Ping, Speed, Score and
Uptime columns measured from Japan. The *list* is a legitimate discovery
source for a low-priority tier. The measurements are not, from anywhere but
Japan; see "Cut" in `PLAN.md`.

---

## Technique survey

Tagged as originally written. Items marked "adopted" are now implemented; see
`docs/measurement.md` for how.

### Measurement

- **Adopted — TCP/443 fallback when ICMP fails.** Many relays null-route ICMP.
- **Adopted — discard the first probe per relay.** Cold ARP and route
  resolution skew the first sample. Ookla, Cloudflare and LibreSpeed all do
  this. (The implementation turned out to be much subtler than the idea; see
  `docs/measurement.md`.)
- **Adopted — resolve hostnames once, probe IPs, and resolve over DoH.** The
  local resolver may be hijacked, geo-skewed, or behind a captive portal.
- **Adopted — median, not mean.**
- **Open — real WireGuard handshake-init packet.** A 148-byte fixed-format UDP
  packet timed against the relay's actual WireGuard port would reflect real
  reachability where ICMP lies. Needs the relay's WireGuard public key, which
  Mullvad, NordVPN and AirVPN expose. Reference: `cloudflare/boringtun`.
- **Open — TLS ClientHello to the OpenVPN port** for OpenVPN-only relays. More
  truthful than a bare TCP SYN.
- **Open — small-payload HTTPS latency phase**, LibreSpeed-style, for relays
  with a public HTTPS endpoint. Robust against ICMP rate-limiting.

### Selection under a small probe budget

- **Adopted — two-stage filter.** Geofilter to top-K by haversine, then probe.
- **Adopted — sticky preference / hysteresis**, as opt-in anti-flap rather than
  a default.
- **Open — hedged probes for the final contenders.** For the top few, send two
  probes in parallel and take the first reply ("The Tail at Scale").
- **Speculative — UCB / Thompson sampling across runs**, so the candidate set
  does not ossify around whatever won the first time.
- **Speculative — Vivaldi network coordinates or iPlane-style anchor
  prediction.** Probe 5-10 anchors per provider and predict the rest. At
  NordVPN's ~8800 servers this is the only honest answer to "rank the whole
  fleet cheaply", and also by far the most work.

### Geo and context

- **Open — invalidate geo cache on default-route change** (`route monitor` on
  macOS, `ip monitor` on Linux). Network-fingerprint history is wrong without
  it and it is cheap to detect.
- **Speculative — M-Lab NDT7 locate-API pattern**: ask a meta-service for the
  nearest candidates, probe those.
- **Speculative — AS-path divergence as a tiebreaker.** When two relays tie,
  compare the last hops of a traceroute: if they share a path, ranking between
  them is meaningless; if not, the slower one is a genuinely different route
  worth keeping as a backup.

### Anti-patterns

- ICMP-only ranking, which silently demotes relays that null-route ICMP.
- Full sequential sweeps of every relay: slow, wasteful, and looks abusive.
- Treating provider-published load as a primary signal. Stale and gameable.
- Pinging hostnames without controlled resolution.
- Caching probe results across network changes without invalidating on
  default-gateway or public-IP change.
- Drifting into a connection manager.

---

## Sources

- `z3d6380/nordPing`: https://github.com/z3d6380/nordPing
- `mrzool/nordvpn-server-find`: https://github.com/mrzool/nordvpn-server-find
- `trishmapow/nordvpn-tools`: https://github.com/trishmapow/nordvpn-tools
- `malgr/NordVPN-Server-Lister`: https://github.com/malgr/NordVPN-Server-Lister
- `openpyn-nordvpn`: https://jotygill.github.io/openpyn-nordvpn/
- `grant0417/mullvad-ping`: https://github.com/grant0417/mullvad-ping
- `ip-address-list/nordvpn`: https://github.com/ip-address-list/nordvpn
- Gluetun: https://github.com/qdm12/gluetun
- AirVPN API docs: https://airvpn.org/faq/api/
- AirVPN status API: https://airvpn.org/api/status/?format=json
- PIA server list: https://serverlist.piaservers.net/vpninfo/servers/v6
- PIA manual-connections: https://github.com/pia-foss/manual-connections
- Mullvad relay API: https://api.mullvad.net/www/relays/all/
- Mullvad app relay/location API: https://api.mullvad.net/app/v1/relays
- NordVPN inventory: https://api.nordvpn.com/v1/servers
- Proton VPN public server page: https://protonvpn.com/vpn-servers
- ExpressVPN public server page: https://www.expressvpn.com/vpn-server
- ExpressVPN manual configuration docs:
  https://www.expressvpn.com/support/manage-account/find-manual-configuration-credentials/
- VPN Gate public CSV: https://www.vpngate.net/api/iphone/
- mullvadvpn-app relay selector (Rust): https://github.com/mullvad/mullvadvpn-app
- ProtonVPN linux-cli-community: https://github.com/ProtonVPN/linux-cli-community
- cloudflare/boringtun: https://github.com/cloudflare/boringtun
- LibreSpeed speedtest-cli: https://github.com/librespeed/speedtest-cli
- cloudflare/speedtest: https://github.com/cloudflare/speedtest
- M-Lab NDT7 client: https://github.com/m-lab/ndt7-client-go
- fujiapple/trippy: https://github.com/fujiapple/trippy
- Vivaldi network coordinates (Dabek et al., 2004):
  https://pdos.csail.mit.edu/papers/vivaldi:sigcomm/
- iPlane Nano (Madhyastha et al., 2009):
  https://web.eecs.umich.edu/~harshavm/iplane/
- "The Tail at Scale" (Dean & Barroso, 2013):
  https://research.google/pubs/the-tail-at-scale/
