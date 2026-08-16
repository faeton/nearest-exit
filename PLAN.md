# Nearest Exit — plan

What this tool is, what it does today, and what is worth building next. For how
the measurement works, read [docs/measurement.md](docs/measurement.md); for
what each provider's API does and does not give us, read
[docs/provider-notes.md](docs/provider-notes.md). The survey work that shaped
the design has moved to [docs/research-log.md](docs/research-log.md) — it is a
record, not a specification, and keeping it here made this document unreadable
and, worse, made stale research look like a commitment.

## Core principle

Do not trust provider recommendations as ground truth.

Provider metadata is for *discovering* candidate relays. Ranking them is the
job of measurement taken from the machine running the tool. Anything that is
not a measurement — the user's provider preference, the provider's reported
load, this tool's own history — is policy, and policy must be visible,
separable and off or minimal by default.

That principle has teeth. It is why NordVPN candidates come from `/v1/servers`
rather than `/v1/servers/recommendations`, why candidate ordering inside a city
ignores reported load, why `scan` applies no preferences unless asked, and why
several otherwise reasonable backlog items are cut outright below.

## Problem statement

A VPN client chooses a server using region, reported load, commercial policy,
protocol availability, account tier, cached recommendations and coarse
geolocation. That can produce a server that is geographically plausible but not
the fastest or most stable path from the connection you are actually on.

Nearest Exit should answer:

- Which relay is closest from this network right now?
- Which relay is fastest within a country or city?
- Which relay is fastest for a given protocol?
- Is the provider client making a strange choice compared with direct
  measurement?
- How stable are the top choices over several rounds?

It is a measurement and recommendation tool. It is not a VPN client.

## Where it stands

Everything in this section is implemented today.

**Providers.** Mullvad, NordVPN, AirVPN and PIA, each behind a
`fetch_relays(cache, refresh)` adapter that normalizes into one `Relay` model
and preserves the raw provider fields in `metadata`. Adapters do not rank and
do not probe. Metadata is cached for 24 hours with atomic writes and
miss-on-corruption reads.

**Commands.**

- `nearest-exit` — detect location, gather candidates per provider, probe,
  rank, print one best relay plus alternatives plus a per-country "nearby"
  line. `--country`, `--scope` / `--here` / `--nearby` / `--global`,
  `--coords`, `--lookup`, `--rounds`, `--best`, `--alts`, `--json`, `--why`.
- `nearest-exit scan` — single-provider (or `--provider all`) ranking on
  measurement alone. `--country`, `--city`, `--protocol`, `--technology`,
  `--top`, `--count`, `--timeout`, `--concurrency`, `--geofilter`, `--refresh`,
  `--no-tcp-fallback`, `--include-inactive`, `--owned` / `--no-owned`,
  `--json`, `--why`, `--preferences`, `-v`.
- `nearest-exit history` — relays that measured best on this network.
  `--window`, `--any-network`.
- `nearest-exit prefs` / `prefs init` / `prefs show`.
- `nearest-exit doctor`.

**Measurement.** ICMP through the system `ping`, TCP-connect fallback on
failure, SOCKS5 when explicitly requested. Warm-up packet identified by
`icmp_seq` and discarded. Median RTT, jitter, loss and recorded attempt counts.
Multi-entry relays probed concurrently with the best target chosen on cost, not
raw RTT. `--rounds N` merges rounds and flags flappy relays. Concurrency
bounded at both the relay and the probe-target level. Hostnames resolved over
DoH, never the system resolver.

**Ranking.** One shared scoring model for both commands, in milliseconds of
equivalent latency, split into `measured_cost_ms` and `effective_cost_ms` so
the measurement/policy boundary is visible in the output and in JSON. Loss is
superlinear but discounted by a Wilson lower bound for sample size. `--why`
prints the derivation.

**Geography.** Relay coordinates for all four providers: published by NordVPN,
resolved through an embedded 103-city table for the other three, falling back
to a country centroid (113 entries) that carries a distance penalty so a coarse
guess cannot outrank a known position. Nearby countries are computed from
centroids built out of the relay coordinates themselves.

**Preferences and history.** Provider preference as absolute millisecond
penalties, anchored at zero and capped at a 200ms spread, with legacy
multiplicative `weights` converted on load and a warning saying what to write
instead. `others_allowed` / `others_threshold_ms` govern non-preferred
providers and compare *measured* cost. History is a local SQLite database keyed
by a hashed network fingerprint, records the measured ordering, and is
consulted for ranking only when `[history] sticky` is on.

**Output discipline.** stdout carries the final table or JSON and nothing else;
progress, warnings and narration go to stderr.

## Roadmap

Ordered by how much each improves the answer, not by how easy it is.

### Next

- **Scriptable output.** A `--quiet` (or `--best-only`) mode that prints one
  bare hostname or IP, so the result can be piped into a provider client or a
  WireGuard config generator. This has been documented before it existed; it
  should now exist.
- **`explain <relay>`.** `--why` explains relays that are already in a result.
  Explaining one named relay — probe it, show its cost derivation, show where
  it would have ranked — is the missing half.
- **Config and flag consistency.** `scan --timeout` ignores
  `defaults.timeout` while `--top` and `--count` honour their config
  equivalents. The built-in default scope is `here` while the config `prefs
  init` writes says `nearby` and the `--nearby` help text calls itself the
  default. Pick one answer for each and make every surface agree.
- **`--ignore-vpn-route-warning`**, and a cleaner story for what the tool does
  when it is run inside a tunnel (currently: warns and measures anyway).
- **`--no-cache` and `--cache-dir`.** Both have been documented and neither
  exists; `--cache-dir` in particular makes development and testing tolerable.

### After that

- **`list` subcommands** — countries, cities, providers, protocols — reading
  normalized relay data without probing. Primarily a discovery-debugging tool,
  which is exactly when you need it.
- **Exports.** CSV and Markdown alongside JSON.
- **`prefs suggest`.** If a non-preferred provider consistently measures better
  on this network, say so as a one-line nudge and let the user adopt it
  explicitly. Never rewrite the user's preferences.
- **Probe depth.** A real WireGuard handshake-init packet timed against the
  relay's actual WireGuard port, for relays whose public key the provider
  publishes; a TLS ClientHello against the OpenVPN port for OpenVPN-only
  relays. Both are more truthful than a TCP SYN, and both are the honest answer
  to "entry-IP RTT is not tunnel RTT".
- **IPv6 probing.** Relays already carry IPv6 addresses and nothing probes
  them.
- **Geo cache invalidation on default-route change.** Network-fingerprint
  history is wrong across a network change that the tool did not notice.
- **Hedged probes for the final contenders.** Two probes in parallel for the
  top few, take the first reply, to cut tie-break noise cheaply.

### Speculative

Ideas that may be right and are not specified. Nothing here should be built
against this description without designing it first.

- A normalized capability model beyond `protocols` — port forwarding, P2P,
  multihop, obfuscation, virtual location — so provider-specific filters do not
  become CLI flag soup. Deliberately not written out as a dataclass here; a
  previous version of this document specified one in full detail and it was
  mistaken for a contract for months.
- More providers. In rough order of how public and structured their metadata
  is: ExpressVPN via user-supplied `.ovpn` import, Proton VPN, IVPN, Surfshark,
  Windscribe, Perfect Privacy. See `docs/research-log.md` for what is known
  about each. Any relay that does not come from an official live endpoint must
  be labelled as such in the output.
- A Gluetun `servers.json` import as an interoperability source for providers
  with no usable public endpoint.
- Latency prediction from a small set of anchors (Vivaldi-style network
  coordinates). At NordVPN's ~8800 servers this is the only cheap way to rank
  a whole fleet, and it is a research project rather than a feature.
- Adaptive re-probing across runs, so the candidate set does not ossify around
  whatever won the first time.
- Showing what the provider's own client would have chosen, side by side with
  the measurement — clearly labelled, and never as a ranking input.
- A local dashboard. Only once the CLI contract is stable.

### Cut

Removed from the backlog because they contradict the premise. Recorded here so
they do not quietly come back.

- **Filtering or ordering candidates by provider-reported load** (`--max-load`,
  `--load-below`, and openpyn's rule that skips servers reporting load below
  6). This is the vendor's own quality number deciding which servers ever get
  measured — the exact defect that was fixed in NordVPN's `spread()`, where
  sorting each city bucket by load meant a busy relay with better peering could
  never become a candidate. It is also self-fulfilling. Load survives as a
  small, clearly-labelled tiebreaker applied *after* the measurements are in.
- **Using VPN Gate's Ping / Speed / Score columns as a prior for probe
  ordering.** They are measurements taken from Japan and are meaningless from
  anywhere else. If VPN Gate is ever added, only the server *list* is usable.
- **Using PIA's server list as a "single-shot prior" of load and coordinates.**
  Cut on principle, and factually impossible besides: the v6 payload exposes
  neither. Its `geo` field is a boolean virtual-location flag and there is no
  load figure anywhere in it.
- **Ranking or shortlisting from any provider's "recommended" endpoint.**
  Already removed for NordVPN, where it meant re-ordering a list NordVPN had
  already filtered. Recommendations survive only as a visibly-degraded fallback
  when the inventory fetch fails.
- **A `SourceQuality` enum as specification, and a `--source-quality
  official-live` default filter.** The underlying need — label anything that
  did not come from an official live endpoint — is real and is kept as a
  one-line rule under Speculative. The enum was specified in detail here for
  months without existing, which is worse than not mentioning it.
- **The old 0-100 `score` formula.** Superseded by millisecond costs, which are
  comparable across runs and mean something on their own.
- **Streaming-service-specific hardcoded server ranges**, in any form.

## Non-goals

- Connecting or disconnecting tunnels.
- Storing provider credentials, or authenticated scraping of a user's account.
- Mutating a provider client's configuration.
- Predicting throughput from latency.
- Treating geographic distance as a ranking signal. It selects candidates; it
  never scores them.
- Depending on private or authenticated APIs.
- Per-protocol throughput estimation. Reachability, latency, jitter and loss
  are the contract.

## Security and safety rules

These are settled and should not be relitigated:

- Never build shell commands by string concatenation; never pass
  provider-supplied values through a shell.
- Keep probe concurrency bounded at both the relay and the probe-target level,
  because self-induced congestion is indistinguishable from a lossy relay.
- Cache provider metadata; do not hammer provider endpoints.
- Store no raw network identifiers in history — the fingerprint is a hash.
- Fail visibly. A degraded run (fallback endpoint, missing location, no
  reachable relay) must say so rather than looking like a normal result.

## Open questions

- What should happen to a relay whose provider reports degraded health? AirVPN
  relays with `health != "ok"` are currently marked inactive and excluded
  entirely, which is a stronger action than the ranking penalty originally
  imagined. Excluding is defensible; it should be a decision, not an accident
  of how `active` was derived.
- Should `defaults.scope` default to `here` or `nearby`? Three surfaces
  currently give three answers.
- Should there be a per-provider probe budget, so one provider's 8800-server
  inventory cannot dominate a run's time?
- How should a relay measured only over TCP be compared with one measured over
  ICMP? Today they share a column and a TCP number silently includes a
  handshake.
- Is a "fastest country near me" mode worth its own command, or is the
  existing `Nearby:` line enough?
- Should the old `mullvad-server-ping` CLI survive as a compatibility shim?
