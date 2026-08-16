# Nearest Exit

Measure VPN relays from your own network and rank them yourself, instead of
trusting the provider's recommendation.

A VPN client picks a server using region, reported load, commercial policy and
coarse geolocation. That often produces a server that is geographically
plausible but not the fastest path from where you actually are. Nearest Exit
uses provider metadata only to *discover* candidate relays, then probes them
from this machine and ranks them on what came back.

Supported providers: Mullvad, NordVPN, AirVPN, PIA. Python 3.11+, standard
library only, macOS and Linux.

## Install

```sh
pip install -e .
nearest-exit doctor
```

`doctor` prints the platform, whether `ping` is available, whether your default
route already looks like a VPN tunnel, and where the cache and config live. If
you are already connected to a VPN, disconnect first: every command warns about
it, because measuring from inside a tunnel measures the tunnel.

## Use

```sh
nearest-exit                          # the headline command: best exit + alternatives
nearest-exit --why                    # ...and show how each ranked number was built
nearest-exit --country DE             # pretend you are in Germany
nearest-exit --here                   # only relays in your own country
nearest-exit --global                 # also sample every country a provider serves
nearest-exit --rounds 3               # probe three times; useful on flappy links
nearest-exit --json                   # machine-readable, on stdout only
```

`nearest-exit` with no arguments detects your public location, fetches relay
metadata for every provider, picks candidates near you, probes them, and prints
one recommendation plus alternatives. The shape of it, with made-up numbers:

```text
Best:
  nordvpn   de1045                Frankfurt, Germany (DE)   wireguard   icmp→185.0.113.1   19.7ms ±2ms   loss 0%  load 22%  = 20.8ms  (in-country)
Alternatives (best of each other provider first):
  airvpn    Adhil                 Frankfurt, Germany (DE)   wireguard   icmp→198.51.100.1  21.0ms        loss 0%  load 31%  = 21.9ms  (in-country)
  mullvad   de-fra-wg-401         Frankfurt, Germany (DE)   wireguard   icmp→203.0.113.1   24.8ms        loss 0%            = 24.8ms  (in-country)
Nearby: Netherlands (NL) +6ms (mullvad)   Switzerland (CH) +9ms (nordvpn)
```

The trailing `= 20.8ms` is the measured cost; when a preference or the history
bonus moves a relay, a second `→ ranked 30.8ms (+10.0)` follows it.

Everything except the result — progress, warnings, the "You:" line, the
research narration — goes to stderr, so `nearest-exit | tail -1` is a relay and
not chatter.

### `scan`

`scan` is the audit trail. It ranks a whole provider on measurement alone, with
no preferences applied unless you ask, so there is always a way to see what the
network actually said.

```sh
nearest-exit scan --provider mullvad --country se --top 10
nearest-exit scan --provider all --geofilter 40 --json
nearest-exit scan --provider nordvpn --technology wireguard_udp --city Dubai
nearest-exit scan --provider pia --protocol socks5     # probe SOCKS5 endpoints
nearest-exit scan --preferences                        # opt in to config penalties
```

Useful flags: `--provider {mullvad,nordvpn,airvpn,pia,all}`, `--country`,
`--city`, `--protocol`, `--technology`, `--top`, `--count`, `--timeout`,
`--concurrency`, `--geofilter K`, `--refresh`, `--no-tcp-fallback`,
`--include-inactive`, `--owned` / `--no-owned`, `--json`, `--why`, `-v`.

`--geofilter K` probes only the K relays nearest your detected location, which
keeps `--provider all` (a thousand-odd relays pooled) to a sensible runtime.

Two things worth knowing about NordVPN's size. `scan --provider nordvpn` ranks
50 candidates spread round-robin over the inventory's `(country, city)`
buckets, not all ~8800 servers; the default flow asks for 500. Narrow with
`--country` to spend that budget where you care. The spread is deterministic
and deliberately ignores NordVPN's reported load, so a busy relay with better
peering can still become a candidate.

### `history`, `prefs`, `doctor`

```sh
nearest-exit history --window 30      # relays that measured best on this network
nearest-exit history --any-network    # ...across every network seen, no lookup
nearest-exit prefs init               # write a commented config.toml
nearest-exit prefs show               # what the tool actually loaded
nearest-exit doctor
```

History stores the measured ordering, not the recommended one, keyed by a
hash of your ASN, default-route interface and public IP /24 prefix. Raw network
identifiers are never written to disk.

## How ranking works

Each relay's **measured cost** in milliseconds is its median RTT, plus a
superlinear packet-loss penalty discounted for how few packets it is based on,
plus half its jitter. Its **effective cost** is that number plus everything
that is not a measurement: provider-reported load, your provider preference,
and the history bonus. Relays are ordered by effective cost, and both numbers
are always printed, so you can see when policy moved something.

With no config file the two are equal — there is no preference, load is the
only non-measured term, and history is off. `--why` breaks either number down
term by term. The full derivation, the constants, and the limits are in
[docs/measurement.md](docs/measurement.md).

## Configuration

`~/.config/nearest-exit/config.toml` (XDG-respecting; override with
`NEAREST_EXIT_CONFIG`). `prefs init` writes a fully commented file that changes
nothing until you uncomment something. That is the honest default: no
preferences means pure measurement.

```toml
[providers]
# Providers you pay for, most to least preferred. Relays from these are always
# shown. Listing every provider is the same as listing none.
order = ["nordvpn", "airvpn"]

# Milliseconds added to a provider's measured cost before ranking, so a
# less-preferred relay must be that much faster to win. Absolute, not
# multiplicative: 10ms means 10ms on fibre and on satellite alike. Unlisted
# providers sit at 0, the lowest entry is normalised to 0, and the spread is
# capped at 200ms.
penalties_ms = { nordvpn = 0.0, airvpn = 5.0, pia = 10.0, mullvad = 15.0 }

others_allowed = true       # still probe and surface providers not in `order`
others_threshold_ms = 5.0   # ...but only if they beat the best preferred by this

[defaults]
feature = "wireguard"   # protocol filter applied to the default flow
scope = "nearby"        # here | nearby | global
top = 3
count = 5               # packets per probe
timeout = 2.0

[history]
sticky = false          # give past winners a head start (anti-flap, not measurement)

[geo]
lookup = "ipinfo"       # ipinfo | stun | none
# country = "YE"
# coords  = [15.5, 48.5]
# mmdb_path = "~/.local/share/nearest-exit/GeoLite2-City.mmdb"
```

A bad value never stops a command: it is reported as a warning on stderr and
the built-in default is kept.

If you have an older config using `providers.weights`, it still loads. Weights
are converted to millisecond penalties at a 30ms reference and the warning
prints the exact `penalties_ms` table to paste in.

## Limitations

Stated plainly, because they bound how much the answer is worth.

- **Probes measure the path to the relay's entry IP, not the tunnel.** ICMP or
  a TCP connect to the public entry address tells you about reachability and
  round-trip time to that address. It does not tell you about the relay's
  egress path, its bandwidth, or how WireGuard will behave once encapsulated.
  Treat the ranking as "which entry point is closest on this network", not
  "which VPN will be fastest".
- **Provider preference, provider-reported load and history are policy, not
  measurement.** That is why preference is empty by default, history is off by
  default, `scan` ignores both unless asked, and every one of them is shown as
  a separate term rather than folded into one opaque score.
- **At small packet counts, close relays are ordered by noise.** Five packets
  per relay cannot separate two relays a millisecond apart. `--rounds N` and
  `scan --count N` buy resolution at the cost of time.
- **Only NordVPN publishes per-relay coordinates.** For the other three,
  positions come from an embedded city table, falling back to a country
  centroid where the provider's label names no city. Country-precision relays
  carry a distance penalty so they cannot outrank relays whose position is
  known. See [docs/provider-notes.md](docs/provider-notes.md).
- **Networks that block ICMP fall back to TCP/443**, which measures a
  handshake against whatever answers on that port. Networks that block both
  produce no ranking at all, and the tool says so.
- **No connection management.** Nearest Exit never connects, disconnects, or
  touches your provider's client or credentials. It prints a hostname.

## Documentation

- [docs/measurement.md](docs/measurement.md) — how a relay's cost is computed,
  what is measurement and what is policy, and what the numbers mean.
- [docs/provider-notes.md](docs/provider-notes.md) — per-provider endpoints,
  what they do and do not expose, and the quirks worth knowing.
- [PLAN.md](PLAN.md) — roadmap and product shape.
- [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
