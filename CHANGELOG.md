# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Nothing has been
released yet: version `0.0.1` in `pyproject.toml` is a placeholder and the
whole of this file describes unreleased work.

## [Unreleased]

### Breaking

These change behaviour for anyone who already has a config file or a script
that reads the output.

- **`providers.weights` is replaced by `providers.penalties_ms`.** Weights
  were multiplicative and divided the measured cost, so the same setting meant
  something different on every link: weight `0.7` cost 8.6ms on a 20ms fibre
  link and 86ms on a 200ms satellite link. "I prefer NordVPN a bit" silently
  became "never pick Mullvad" the moment the link got slow. Penalties are
  absolute milliseconds and mean the same thing everywhere. Existing `weights`
  still load, converted at a 30ms reference latency, and the warning prints
  the `penalties_ms` table to copy into the config.
- **`--here` no longer takes a country code.** It is now a scope flag meaning
  "only consider relays in my own country", alongside `--nearby`, `--global`
  and `--scope {here,nearby,global}`. Use `--country CC` for the country
  override, which is what `--here CC` actually did.
- **JSON field `effective_rtt_ms` is gone**, replaced by two fields:
  `measured_cost_ms` (what this network measured) and `effective_cost_ms`
  (what the relay was ranked by, after provider preference and history). Both
  appear in `--json` and in the human table, and with no config file they are
  equal.
- **`scan` no longer applies provider preferences by default.** It ranks on
  measurement alone so there is always a way to see what the network said;
  pass `--preferences` to apply the config's penalties, which it announces on
  stderr when it does. (`scan` previously did not read the config at all, so
  it also gains config validation warnings.)
- **Sticky history is off by default** (`[history] sticky = false`). A relay
  that won here before getting a head start is a preference for stability, not
  a measurement.
- **With no config file there is now no provider preference at all.** The
  built-in defaults used to be `order = ["nordvpn", "airvpn", "mullvad",
  "pia"]` with weights; both are now empty, so a fresh install ranks purely on
  measurement.
- **`prefs init` writes a neutral config.** The shipped file used to switch the
  policy engine on with a provider order, 5-15ms penalties and a 5ms
  threshold. It now changes nothing until something is uncommented.
- **Default probe count is 5, not 3.** At n=3 a single dropped packet reads as
  33% loss, which is enough noise to reorder the table on its own.
- **`scan --top` and `scan --count` default to the config**
  (`defaults.top`, `defaults.count`) instead of hardcoded 10 and 4. With no
  config that is 3 rows and 5 packets.
- **Human-mode narration moved from stdout to stderr.** Progress, research
  lines and the reproduce-this footer are no longer on stdout, so
  `nearest-exit | tail -1` returns a relay rather than chatter.

### Fixed

- `nearest-exit` returned nothing when geolocation failed: with no country and
  no coordinates it selected zero candidates and exited 1 with a full relay
  list already in hand. It now samples across countries, or ranks by distance
  when only coordinates are known, and says which.
- `--concurrency 0` hung forever, because `asyncio.Semaphore(0)` never
  releases. The value is clamped, and the parser now rejects out-of-range
  numbers for concurrency, count, timeout, top, best, alts, rounds and window
  instead of accepting them and failing later.
- A bare `nearest-exit prefs` inherited the root parser's defaults and ran a
  full internet scan. It shows the config.
- One wrongly-typed config value took down every command: `top = "3"` raised
  `TypeError` before any command could run. Values are coerced, and anything
  unusable is reported as a warning with the built-in default kept.
- A provider weight of `inf` made that provider's cost 0.0, so it won
  unconditionally and silently.
- Provider preference was applied twice: once by dividing the cost, then again
  when the threshold compared the already-weighted number. A Mullvad relay
  measured at 20ms became 28.6ms at weight 0.7 and was dropped for not beating
  a 30ms preferred relay, despite being 10ms faster. The threshold now
  compares measured cost, so preference applies exactly once.
- The printed number was not the number the tool ranked by: output showed raw
  median RTT while ordering by something else, and `RankedRelay.reasons` was
  computed and then discarded by both formatters.
- Loss and jitter penalties were too weak to match the documented ranking
  priorities. At `loss * 100`, 5% packet loss cost 5ms, so a lossy relay beat
  a clean one 6ms slower.
- The warm-up discard threw away good data. All three probes dropped
  `samples[0]`, but `samples` holds only successful replies, so when the first
  packet was lost — the cold-path case the discard exists for — a warm sample
  was discarded instead. TCP and SOCKS5 track per-attempt results; ICMP
  identifies the cold packet by its `icmp_seq` rather than assuming it was the
  first reply.
- Packet counts were reconstructed from `len(samples)` and `loss` rather than
  recorded. Exact for a single probe, wrong once rounds with different counts
  merged: an ICMP round of 3 followed by a TCP fallback of 2 gave 4 attempts
  instead of 5 and understated the loss penalty by roughly half. `ProbeResult`
  now carries `attempts`.
- `merge_rounds` and `flappy` keyed on `relay.id` alone. Ids are unique only
  within a provider, so two providers' latency samples could silently merge.
  Both are keyed on `(provider, id)`.
- `_best_probe` chose among a relay's probe targets by raw RTT, so a target
  answering in 10ms while dropping half its packets beat a clean one at 20ms.
  It uses the same cost function that ranks relays.
- The "Nearby" section still selected and sorted on raw RTT, so it could
  advertise a lossy 10ms relay as a country's best, contradicting the ranking
  printed directly above it.
- History recorded the *recommendation*, not the measurement. `rank=1` was the
  post-preference, post-history position, so a preferred relay won on policy,
  was recorded as the winner, and got a bonus next time for having been
  preferred. History now records the measured-cost ordering.
- Provider-reported load was folded into `measured_cost_ms`, which is the
  value the preference threshold compares and the one the output labels
  "measured". Load is a number the provider hands us, so it left that number —
  and then left the ranking entirely; see Changed.
- An interrupted fetch left a truncated cache file that `fresh()` reported as
  fresh and `load()` then raised on, wedging the tool until the cache was
  cleared by hand. Writes go through a temp file and `os.replace`, and an
  unparsable entry reads as a miss.
- DoH resolved the same hostname once per relay per round, and the memo only
  helped after the first result landed — probes fan out together, so every
  task missed and every task asked. Concurrent lookups of one hostname now
  collapse into a single query, with a short TTL on failures.
- `history` re-ran the schema DDL on every connection, including read-only
  queries.
- `scan --geofilter` called `lookup_ipinfo()` directly, so `--lookup none`
  still made a network call and `--coords` was ignored on that path.
- `scan` and the default flow disagreed about ordering because `scan` never
  called `load_config`: the scoring function was shared, the inputs were not.
- Both provider-penalty caps could be exceeded. Clamping ran before anchoring,
  so `{-1e9, +1e9}` became `{-200, +200}` and then anchored to a 400ms spread,
  twice the stated limit; legacy weights bypassed the clamp entirely.
- A legacy config naming a single provider lost its preference: `weights = {
  nordvpn = 2.0 }` converted to one -15ms entry, which anchoring shifted to 0
  while unlisted providers stayed at their implicit 0. Every known provider is
  materialised before anchoring.
- `filter_relays` dropped every relay without an `ipv4`, which guaranteed the
  DoH fallback in `_ensure_ipv4` could never fire.
- `_gather_candidates` took a `centroids` argument its body never used, and
  `flappy()` was called without a provider on results keyed by relay id.
- Deduplication in the neighbour loop was keyed on relay id alone and rebuilt
  the seen-set on every iteration.
- `providers/mullvad.py` used `__import__("json")` inline.

### Changed

- **Provider-reported load is no longer ranked on at all.** It had moved out of
  `measured_cost_ms` but stayed in `effective_cost_ms`, which is the sort key —
  so two identical measurements were still ordered by a number the provider
  supplies about its own server, under a status line reading "ranking on
  measurement alone". It is displayed and reported in `--why` as "shown, not
  ranked on". With no config file, measured and effective cost are now exactly
  equal.
- **A tie is reported as a tie.** The output used to name a `Best:` and then
  note in parentheses that the winner was not meaningful, which is a hedge
  rather than a disclosure. When more leaders fall inside the measurement noise
  band than were asked for, it prints `Tied (N)` and lists them. Tied relays are
  all recorded at rank 1, so the anti-flap bonus cannot be handed to whichever
  one won a coin flip.
- The ICMP warm-up packet is excluded from the loss figure as well as from the
  median. Discarding its RTT because it pays for ARP and route setup, and then
  charging a loss penalty when that same packet is the one that dropped, had
  the tool arguing with itself about whether it was a warm-up or a signal.
- The per-provider "N of M probed" line reports NordVPN's true fleet size.
  `spread()` reduces the inventory before the caller sees it, so it read
  "60 of 500" and made a sample of ~8600 look like the whole fleet.
- **NordVPN candidates come from `/v1/servers`, not
  `/v1/servers/recommendations`.** The tool's central claim is that it does not
  trust the provider's ranking; for NordVPN it was re-ordering a shortlist
  NordVPN had already chosen and never saw a server NordVPN declined to
  recommend. Recommendations remain a fallback when the inventory fetch fails,
  and a degraded run now warns on stderr naming the endpoint and the cause.
- NordVPN requests are sent as sparse fieldsets (`fields[servers.<path>]`),
  taking the full inventory from 33,355,923 bytes in 4.46s to 4,597,952 bytes
  in 1.28s over the wire, with normalized output identical to the raw
  response. The client-side trimming pass is gone; only a small
  `prune_inventory()` remains, because `fields` selects keys and cannot prune
  values.
- Candidate selection within a NordVPN city bucket is neutral and
  deterministic. It used to sort by NordVPN's reported load, so the
  least-loaded box in each city was the only one that could ever be probed —
  the provider deciding who gets measured, and self-fulfilling besides.
- Relay coordinates resolve to the city, not the country. `cities.py` embeds
  103 city coordinates (seeded from Mullvad's own `/app/v1/relays` location
  table, extended by hand) and all four providers now place their relays
  through it. Measured against live payloads: AirVPN 257/257 relays at city
  precision, PIA 39/189 regions at city precision with 150 at country
  precision, Mullvad 587/587 at city precision.
- Country-precision coordinates carry a 750km uncertainty in
  `top_k_by_distance`, so a relay pinned to a country centroid cannot outrank
  one whose position is known. Measured mean displacement from centroid to
  true city was 645km for AirVPN and 1101km for PIA.
- Total in-flight probes are bounded by the concurrency limit rather than
  twice it. Pinging four entry IPs of eighty relays at once induces exactly
  the loss the score then charges for.
- A relay's entry IPs are probed concurrently rather than serially. AirVPN
  publishes up to four per server, which cost four serial `ping` runs per
  relay — about twelve seconds on macOS, where ping's default interval is one
  second.
- Loss is penalised superlinearly (300ms linear + 3000ms quadratic per unit
  loss) but discounted through a Wilson score lower bound, so a single drop is
  weak evidence rather than a 33% loss rate.
- `top_k_by_distance` uses `heapq.nsmallest` instead of a full sort.
- `history` states that identifying the current network requires a lookup, and
  `--any-network` reports across every network seen without one.
- Provider fetches use one `load()`-then-check pattern everywhere, so a cache
  miss is handled the same way in every adapter.
- Listing every provider in `providers.order` now warns: it leaves no "others"
  and makes `others_threshold_ms` inert.
- `--here` is strict. It could recommend an exit in another country: when a
  provider had no relay in the detected country, candidate recovery ran before
  the scope check and fell back to the nearest relays globally. That provider
  now contributes nothing and says why. Without a determinable country,
  `--here` widens to `nearby` and warns.
- `--global` means *also* worldwide. NordVPN's inventory is fetched
  country-filtered to keep it small, so the worldwide sampler only ever saw
  that one country; skipping the filter then cost in-country depth. It now
  merges both fetches. From Montreal: `here` 60 relays in 1 country, `nearby`
  61 in 2, `global` 100 in 41 with the same 60 still local.
- Unknown provider names in `providers.penalties_ms` are dropped before
  anchoring. Anchoring subtracts the minimum, so a typo like `nordvpm = -1000`
  clamped every real provider to the cap and erased the differences actually
  requested.
- PIA's state and province regions are positioned to the subdivision instead
  of the country. 43 US labels sat at the USA centroid (38.0, -97.0), roughly
  1500km from either coast, and that position decides which relays get probed
  at all. 40 regions move from country to region precision; modelling the
  endpoint as population-proportional, mean expected error falls from 1367km
  to 142km. `US East`, `US West`, the Streaming Optimized variants and
  `US Wilmington` stay at country precision — marketing regions are not
  places, and Wilmington DE and NC are 600km apart.
- Nearby countries are chosen only from countries some provider actually
  serves. `nearest_countries` ranked over the whole embedded centroid table,
  which covers the world, so from a location near several unserved countries
  the neighbour budget went to places that could never yield a candidate.
- `defaults.scope` defaults to `nearby`, matching the shipped config and the
  `--nearby` help text. The dataclass said `here`, but nothing read the value,
  so the flow always behaved as `nearby` regardless.
- `scan --timeout` honours `defaults.timeout`, which `--top` and `--count`
  already did. Invisible until now only because both defaults were 2.0.

### Added

- `--scope {here,nearby,global}` plus `--here` / `--nearby` / `--global`, and
  `defaults.scope` from config is finally consumed rather than only echoed by
  `prefs show`. `here` searches your own country, `nearby` adds the nearest
  other countries, `global` also samples across every country the provider
  serves.
- `--why` on the default flow and on `scan`, showing how each relay's ranked
  cost was built, term by term.
- `scan --preferences`, to opt into the config's provider penalties.
- `history --any-network`.
- A guard against probing unroutable addresses (RFC1918, loopback, link-local,
  multicast). Provider metadata is not always about the public internet, and
  without this a metadata quirk could point the prober at the user's own LAN.
- `ProbeResult.attempts`, `RankedRelay.measured_cost_ms` and
  `RankedRelay.effective_cost_ms`.
- **`--probe {auto,icmp,tcp,openvpn,socks5}`, and an OpenVPN control-channel
  probe.** Every existing probe measures the path to the relay's IP stack;
  `--probe openvpn` measures the VPN daemon itself, by timing a 14-byte
  plaintext `P_CONTROL_HARD_RESET_CLIENT_V2`. PIA answers it with a
  `HARD_RESET_SERVER_V2` over UDP on 8080/853; AirVPN and NordVPN run
  `tls-auth`, so they read it, fail the HMAC and close over TCP/443 — also a
  daemon round trip, and verifiably so (connecting and sending nothing holds
  the connection open six seconds; sending the reset closes it one RTT later).
  Mullvad has no OpenVPN fleet, so it reports no target rather than a dead
  relay. Measured against ICMP on 15 PIA regions, sequential and
  ABBA-interleaved: median delta -1.5ms, range -8.2 to +7.2ms, 0 of 14
  disagreeing by more than 10ms — so ICMP is usually a good proxy, and this
  lets you check rather than assume.
- **`--probe ikev2`**, a second daemon-plane probe, NordVPN only. Sends a
  216-byte `IKE_SA_INIT` proposing only DH group 1 (MODP-768) and times the
  `NO_PROPOSAL_CHOSEN` refusal. Being refused is the design: an accepted
  exchange makes the responder do a 2048-bit modexp and bakes +2.7 to +6.0ms
  of its CPU into the RTT, trips RFC 7296 cookie machinery within three
  samples, and returns a 437-byte reply; a refusal costs the responder
  nothing, creates no half-open SA, and answers 36 bytes to a 216-byte
  request. Client cost is about a microsecond per probe, mostly the
  `os.urandom(8)` for the initiator SPI; everything after it is a constant. Excluded for PIA on purpose: PIA answers IKE, but its listener is
  0/3 to 3/3 with 1.5-2.3s outliers on seven regions where its OpenVPN
  listener is 3/3, and a two-second sample in a latency ranking is a
  fabricated answer. AirVPN and Mullvad run no IKEv2.
- `defaults.probe` in config. `--probe` is deliberately a separate axis from
  `--protocol`: one decides which relays qualify, the other how they are
  measured. Selecting the SOCKS5 probe from a relay *filter* was the muddle
  this replaces.
- `subdivisions.py`, US state and Canadian province population-weighted
  centres, plus a `GEO_PRECISION_REGION` tier carrying 150km of uncertainty in
  `top_k_by_distance` against a country's 750km.
- `schema_version` in the default flow's JSON object, so a consumer can fail
  loudly rather than silently misreading the renamed cost fields. (`scan
  --json` still emits a bare array and carries no version.)
- Disclosure of how much of each provider was actually measured. Provider
  lines read `31 of 550 probed (nearest 29 in CA, +2 from nearby countries)`,
  and the footer names the scope, so a ranking over 130 of ~9800 relays cannot
  be mistaken for a ranking over all of them.
- Disclosure of statistical ties. When the top relays fall inside the wider of
  their two measurement spreads, the output says the winner among them is not
  meaningful instead of presenting an arbitrary tiebreak as a result.
  `statistical_ties` is in the JSON.
- `metadata["geo_precision"]` on AirVPN, PIA and Mullvad relays, recording
  whether a coordinate came from the city table or a country centroid.
- `LICENSE` (MIT), `CHANGELOG.md`, `docs/measurement.md`,
  `docs/provider-notes.md` and `docs/research-log.md`.

### Removed

- Mullvad SOCKS5 targets, which never worked. 574 of 587 Mullvad relays
  publish `socks_name` and `socks_port`, so normalising them looked like all
  that was needed to make `--protocol socks5` work outside PIA — an earlier
  commit on this branch claimed exactly that. It was wrong: every one of those
  names resolves into `10.124.0.0/16` (12 of 12 sampled), because Mullvad's
  proxies are reachable only from *inside* a Mullvad tunnel, which is the
  state this tool runs before. The result was an unreachable target on every
  relay and a `socks5` protocol tag that made `--protocol socks5` select
  relays it could never measure, reporting the timeout as though the relay
  were slow. No supported provider currently exposes a publicly reachable
  per-relay SOCKS5 endpoint: PIA advertises a `proxysocks` group but exposes
  the service key on 0 of 189 regions, NordVPN's inventory has no socks
  technology, and AirVPN publishes none. `probes/socks5.py` is kept — it is
  correct, and it will work the moment a provider publishes a reachable
  endpoint.
- `GEO_PRECISION_EXACT`. It was defined, exported and documented, and nothing
  ever set it — because there is nothing to set it to. NordVPN is the only
  provider returning coordinates and they are per-city, not per-machine: 800
  sampled servers across 30 cities share exactly one coordinate each, and
  London and Paris are byte-identical to Mullvad's independently published
  city table. NordVPN relays are now labelled `city`, which is what they are.
- NordVPN servers advertising only `socks` or `openvpn_xor_*` — about 170 of
  8832 — are dropped from the inventory. They map to no protocol this tool can
  use as an exit, so probing them burns a candidate slot on something
  unusable. This is a capability filter, not a quality one.
- Relays that cannot carry exit traffic are no longer ranked. A live run
  recommended `ca-mtr-br-001`, a Mullvad bridge, as the fourth best exit;
  bridges are entry obfuscation and socks-only servers are proxies.
  `filter_relays` requires wireguard, openvpn or ikev2 unless a protocol was
  asked for explicitly, so `--protocol socks5` still reaches SOCKS endpoints.
- `tests/fixtures/mullvad_sample.json` was not a capture: it carried
  `latitude` and `longitude` fields that `https://api.mullvad.net/www/relays/all/`
  does not return, which hid the fact that Mullvad relays had never had
  coordinates. It is now a verbatim four-relay capture.
