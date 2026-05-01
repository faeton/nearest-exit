# Nearest Exit

## Working Name

Chosen name: **Nearest Exit**

Why this name:

- It describes the actual user goal: find the nearest usable VPN exit server from the current network.
- It is provider-neutral. The tool can compare Mullvad, NordVPN, and later any provider with discoverable relay metadata.
- It avoids implying that geographic distance is the only metric. The "nearest" exit should mean the best measured path from here, not just the shortest line on a map.
- It works as a CLI name: `nearest-exit`.

Other names considered:

- `vpn-nearest`: clear, but bland.
- `exit-radar`: memorable, but slightly vague.
- `relayrank`: accurate, but sounds like a library rather than a tool.
- `pingexit`: too narrow because ICMP should be only one signal.
- `routepick`: good, but less obvious for VPN users.

## Problem Statement

VPN clients often choose servers in a way that feels wrong from the user's actual location and current network path. A provider may choose a relay based on region, server load, commercial policy, available protocol, account features, cached recommendations, or coarse geolocation. That can produce a server that is geographically plausible but not actually fastest or most stable from the current connection.

Nearest Exit should independently rank VPN relays by measured reachability and latency from the machine running the tool. The tool should answer:

- Which provider relay is closest from this network right now?
- Which relay is fastest within a country, city, or region?
- Which relay is fastest for WireGuard, OpenVPN, SOCKS-capable relays, or a specific port speed?
- Is the provider client making a strange choice compared with direct measurements?
- How stable are the top choices over multiple rounds?

The first version should not try to be a full VPN client. It should be a measurement and recommendation tool.

## Product Shape

Nearest Exit should start as a CLI, then grow into optional machine-readable output and a small local UI.

### Default Action: `nearest-exit` (no args)

Running `nearest-exit` with no subcommand is the headline action. It must be useful in one keystroke.

What it does, in order:

1. **Detect current context.**
   - Public IP, ASN, ISP, city, country, coordinates (via a single lightweight lookup, e.g. `https://ipinfo.io/json` or `https://ipapi.co/json`, with a fallback).
   - Default route interface; warn if it already looks like a VPN tunnel.
   - DNS resolver, simple latency to a fixed reference (e.g., `1.1.1.1`) for a baseline.
2. **Load user preferences** from `~/.config/nearest-exit/config.toml`:
   - Preferred providers, in order, with weights.
     Example default for this user:
     ```toml
     [providers]
     order = ["nordvpn", "airvpn", "mullvad"]
     weights = { nordvpn = 1.0, airvpn = 0.9, mullvad = 0.7 }
     others_allowed = true       # consider non-preferred if clearly better
     others_threshold = 0.15     # must beat best preferred by 15% score
     ```
   - Default feature profile (e.g. `wireguard`, `socks5`, `p2p`).
   - Default scope (e.g. `same-country`, `same-region`, `global`).
3. **Score the candidate set** using the user's preferred providers first, with non-preferred providers probed in parallel only if `others_allowed`. Apply a per-provider weight to the score so a marginally-better non-preferred relay does not displace a comfortably-good preferred one. Surface non-preferred relays only when they exceed `others_threshold`.
4. **Suggest nearby countries** when no relay in the user's current country is reachable or fast. Use detected coordinates plus relay coordinates to compute a candidate ring of nearby countries, then probe a small sample (e.g. top 3 per neighboring country) before recommending. Travel-aware: if the detected country differs from the last-seen country, show a "you appear to be in X now" line and bias toward X.
5. **Print one clear recommendation** plus a short alternatives list:
   ```text
   You: Berlin, DE — Deutsche Telekom (AS3320), default route via en0
   Best:  nordvpn de1045   wireguard  19.7ms  loss 0%   load 22%   score 95.1
   Also:  airvpn  Adhil    wireguard  21.0ms  loss 0%   health ok score 93.4
          mullvad de-fra-wg-401       24.8ms  loss 0%             score 92.0
   Nearby: NL +6ms  CH +9ms  PL +11ms
   ```
6. **Record the result** to local history so the tool can learn "usual best on this network".

Flags that modify the default action:

```sh
nearest-exit                     # default: preferences + same-country + nearby
nearest-exit --here              # only current country
nearest-exit --nearby            # current + neighboring countries (default on)
nearest-exit --global            # ignore geography, rank globally
nearest-exit --feature socks5    # override default feature profile
nearest-exit --provider any      # ignore preference order for this run
nearest-exit --json              # machine output
nearest-exit --quiet             # print only the chosen hostname (scripting)
```

### Preference Learning

The default action should not be static. If a non-preferred provider consistently wins on this network over N scans, the tool should:

- Surface a one-line nudge: `note: nordvpn has been slower than airvpn on this network in 6 of last 8 scans — consider --provider airvpn`.
- Never silently change the user's preference order.
- Expose `nearest-exit prefs show` and `nearest-exit prefs suggest` to view and adopt suggestions explicitly.

### Geographic Awareness

Use relay coordinates from provider metadata (Mullvad and AirVPN expose them; NordVPN exposes `locations[].country.city.latitude/longitude`; PIA does not but country-level is enough). Compute great-circle distance from the user's detected coordinates only as a tiebreaker and as the seed for the "nearby countries" set — never as a primary score input.

Optional external speedtest signal (V2):

- Ookla and Cloudflare both expose nearest-server lookups that imply a good local-routing baseline. We can call one of these once per network fingerprint to get a "best-case local latency floor" and use it as a sanity check: if the best VPN relay's RTT is within ~10–15ms of the local floor, the result is trustworthy; if not, warn that the path may be congested or the network is throttling ICMP.
- Treat external speedtest data as a calibration signal, not a ranking input. Do not depend on it; default action must work offline-of-speedtest.

Primary CLI examples:

```sh
nearest-exit scan --provider mullvad
nearest-exit scan --provider nordvpn --country us
nearest-exit scan --provider all --top 20
nearest-exit explain --provider mullvad --server se-sto-wg-301
nearest-exit compare --providers mullvad,nordvpn --country de --rounds 3
```

Useful output:

```text
rank provider  server            country city       protocol   ip              score  rtt     loss  jitter
1    mullvad   de-fra-wg-401     DE      Frankfurt  wireguard  146.70.117.2    96.2   24.8ms  0%    1.4ms
2    nordvpn   de1045            DE      Frankfurt  wireguard  185.x.x.x       93.8   26.1ms  0%    2.0ms
3    mullvad   nl-ams-wg-201     NL      Amsterdam  wireguard  169.150.196.2   90.4   32.5ms  0%    1.9ms
```

The output should be easy to parse manually and also available as JSON:

```sh
nearest-exit scan --provider all --json
```

## Core Principle

Do not trust provider recommendations as ground truth.

Use provider metadata only to discover candidate relays. Rank candidates using local measurement from the current network.

## Non-Goals For V1

- Do not connect or disconnect VPN tunnels.
- Do not store provider account credentials.
- Do not mutate provider app configuration.
- Do not promise perfect throughput prediction from ping alone.
- Do not treat geographic distance as the primary signal.
- Do not rely on private or authenticated APIs unless explicitly added later.

## V1 Goals

- Discover Mullvad relays.
- Discover NordVPN relays.
- Normalize both providers into one internal relay model.
- Probe relays concurrently.
- Rank by a clear score.
- Explain why a relay ranked well or poorly.
- Cache provider metadata.
- Keep dependencies small.
- Work on macOS first, then Linux.

## V2 Goals

- Add TCP connect probes for ports that matter to the VPN protocol.
- Add UDP/WireGuard-style handshake probes where practical and legal.
- Add multi-round scans and stability scoring.
- Add local history so the tool learns common best relays for this network.
- Add export formats: JSON, CSV, Markdown.
- Add a local browser dashboard.
- Add optional comparison against the currently selected provider-client server.

## V3 Goals

- Add more providers.
- Add passive route diagnostics.
- Add ASN and ISP awareness.
- Add scheduled background scans.
- Add a small menu-bar helper.
- Add provider-client integration, if safe and user-approved.

## Repository Layout

Initial folder layout:

```text
nearest-exit/
  PLAN.md
  README.md
  pyproject.toml
  src/
    nearest_exit/
      __init__.py
      cli.py
      models.py
      scoring.py
      cache.py
      probes/
        __init__.py
        icmp.py
        tcp.py
      providers/
        __init__.py
        base.py
        mullvad.py
        nordvpn.py
  tests/
    test_scoring.py
    test_models.py
    test_provider_normalization.py
  data/
    .gitkeep
  docs/
    measurement.md
    provider-notes.md
```

This is intentionally boring Python packaging. The current Mullvad pinger is already Python and stdlib-only, so reuse that direction unless a dependency clearly pays for itself.

## Language And Runtime

Recommended stack:

- Python 3.11+
- `asyncio` for concurrency
- `argparse` initially, or `typer` later if CLI complexity grows
- `urllib.request` or `http.client` initially, `httpx` later only if needed
- `subprocess` for system ping
- SQLite for history in V2

Python 3.11+ is the right baseline because:

- It is modern enough for clean async ergonomics.
- macOS users can install it easily.
- The existing Mullvad script is already Python.
- The problem is IO-bound, not CPU-bound.

## Internal Data Model

Use one normalized relay object across all providers.

```python
@dataclass(frozen=True)
class Relay:
    provider: str
    id: str
    hostname: str
    country_code: str | None
    country_name: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    ipv4: str | None
    ipv6: str | None
    protocols: tuple[str, ...]
    active: bool | None
    owned: bool | None
    load: float | None
    capacity: int | None
    metadata: Mapping[str, Any]
```

Use one normalized probe result.

```python
@dataclass(frozen=True)
class ProbeResult:
    relay_id: str
    probe: str
    target: str
    success: bool
    rtt_ms: float | None
    loss: float | None
    jitter_ms: float | None
    samples: tuple[float, ...]
    error: str | None
```

Use one scored result.

```python
@dataclass(frozen=True)
class RankedRelay:
    relay: Relay
    score: float
    primary_rtt_ms: float | None
    loss: float | None
    jitter_ms: float | None
    reasons: tuple[str, ...]
```

## Provider Adapter Contract

Every provider adapter should implement:

```python
class ProviderAdapter(Protocol):
    name: str

    async def fetch_relays(self, cache: Cache) -> list[Relay]:
        ...
```

Adapters must:

- Fetch or load provider metadata.
- Normalize fields into `Relay`.
- Preserve raw provider fields in `metadata`.
- Avoid ranking decisions.
- Avoid probing.
- Fail with clear provider-specific errors.

The ranking pipeline should not know provider-specific schemas.

## Mullvad Adapter

Starting point:

- Reuse logic from `/Users/faeton/Sites/mullvad-server-ping/ping_mullvad.py`.
- Use Mullvad relay metadata as the source of candidates.
- Preserve filters currently supported by the Mullvad pinger:
  - country code
  - country name
  - active state
  - owned/rented
  - relay type
  - SOCKS metadata
  - network port speed

Implementation notes:

- Move fetch/cache code into `providers/mullvad.py`.
- Move ICMP code into `probes/icmp.py`.
- Keep a compatibility wrapper if the old Mullvad CLI should survive.
- Fix Python version mismatch from the existing package before reuse. The old script uses `BooleanOptionalAction`, which means Python 3.9+, despite metadata saying 3.8+.

## NordVPN Adapter

NordVPN discovery needs to be treated as less stable until verified. Do not hard-code assumptions without a provider-notes document and tests with recorded sample data.

Adapter objectives:

- Discover active NordVPN servers.
- Extract hostname or station IP.
- Extract country and city.
- Extract supported technologies when available.
- Extract load when available.
- Normalize server names such as `us1234`, `de1045`, or provider-specific identifiers.

Fallback strategy:

1. Prefer provider metadata endpoint if accessible without credentials.
2. If metadata is incomplete, use generated hostnames only as a fallback.
3. If only hostname ranges are available, make the range explicit in the CLI so users know it is a guess.

Do not clone `nordPing`'s numeric-range approach as the primary implementation. It is useful as a fallback technique, but it misses inactive servers, new naming schemes, provider load, city data, and protocol details.

## Measurement Strategy

V1 should support ICMP because it is simple and broadly understood.

ICMP limitations:

- Some relays or networks block ICMP.
- ICMP latency does not always match WireGuard or OpenVPN session performance.
- ICMP can be deprioritized by routers.
- One packet is too noisy for final recommendations.

V1 defaults:

- `--count 3`
- `--concurrency 100`
- `--timeout 2s`
- `--rounds 1`
- Top 10 output by default

V2 should add:

- TCP connect probes.
- Multiple rounds.
- Median RTT.
- Packet loss percentage.
- Jitter.
- Stability score.

Avoid using only average latency. Median is usually a better default because one slow packet can distort a small sample.

## Probe Types

### ICMP Probe

Purpose:

- Fast first-pass reachability and latency.

Implementation:

- Use system `ping`.
- Use argument lists, never shell strings.
- Parse packet times with platform-aware regex.
- Return all samples, not just one average.

macOS command:

```sh
ping -c 3 -W 2000 1.2.3.4
```

Linux command:

```sh
ping -c 3 -W 2 1.2.3.4
```

### TCP Connect Probe

Purpose:

- Measure whether a TCP endpoint is reachable quickly.
- Useful for OpenVPN TCP, HTTPS metadata endpoints, and provider-specific control ports.

Implementation:

- Use `asyncio.open_connection`.
- Measure connect time.
- Close immediately.
- No application data needed.

### SOCKS5 Probe

Purpose:

- Measure whether provider SOCKS5 endpoints are reachable and responsive.
- SOCKS5 can be more compatible than full VPN tunnels for specific apps, browsers, package managers, CLI tools, and split workflows.
- SOCKS5 is useful when the user wants proxy routing without changing the system default route.

Implementation:

- Add SOCKS5 as both a relay feature and a probe type.
- Use a minimal SOCKS5 handshake.
- Support no-auth SOCKS first.
- Add username/password support later for providers that require it.
- Optionally send a CONNECT request to a configurable target such as `example.com:443`.

Measurements:

- TCP connect time to SOCKS endpoint.
- SOCKS handshake time.
- Optional CONNECT negotiation time.

CLI examples:

```sh
nearest-exit scan --feature socks5
nearest-exit scan --provider mullvad --socks5 --target example.com:443
nearest-exit scan --provider nordvpn --feature proxy --target cloudflare.com:443
```

Scoring:

- SOCKS5 should have its own score profile.
- For app compatibility, successful SOCKS handshake should matter more than ICMP latency.
- If both ICMP and SOCKS are available, show both instead of blending them into one opaque number.

Provider notes:

- Mullvad exposes SOCKS metadata for some relays in its relay API.
- NordVPN metadata can expose proxy technologies and proxy hostnames.
- PIA exposes a `proxysocks` group in its public server list.
- Some providers only expose SOCKS while connected to their VPN tunnel; label these as `in-tunnel-only` if detected or documented.

### UDP Probe

Purpose:

- Better approximation for WireGuard-like connectivity.

Caution:

- UDP reachability is hard to infer without protocol-specific handshakes.
- Do not send malformed protocol traffic at scale.
- For V1, document but do not implement unless there is a clean provider-neutral method.

## Scoring

Score should be explainable and stable.

Initial formula:

```text
score = 100
score -= median_rtt_ms * 0.6
score -= jitter_ms * 1.5
score -= loss_percent * 2.0
score -= provider_load_percent * 0.15
score += active_bonus
score += protocol_match_bonus
```

Clamp score to `0..100`.

Ranking priorities:

1. Successful reachability beats failed reachability.
2. Lower median RTT beats lower average RTT.
3. Lower loss beats slightly lower latency.
4. Lower jitter breaks close ties.
5. Lower provider load can break close ties.

Explain output:

```text
de-fra-wg-401 scored 96.2:
- median RTT 24.8ms
- 0% packet loss
- jitter 1.4ms
- active WireGuard relay
- provider load 18%
```

## Filters

Global filters:

- `--provider mullvad`
- `--provider nordvpn`
- `--provider all`
- `--country us`
- `--country-name Germany`
- `--city Frankfurt`
- `--protocol wireguard`
- `--active`
- `--top 20`
- `--max-rtt 100`
- `--json`
- `--csv`
- `--no-cache`
- `--refresh`

Provider-specific filters:

- Mullvad:
  - `--owned`
  - `--rented`
  - `--socks`
  - `--port-speed 10`
- NordVPN:
  - `--technology wireguard`
  - `--load-below 50`
  - provider-specific group filters if metadata supports them

Provider-specific filters should be accepted only when that provider is selected, or ignored with a clear warning when scanning all providers.

## Cache Design

Cache provider metadata separately:

```text
~/.cache/nearest-exit/
  mullvad-relays.json
  nordvpn-relays.json
  probe-history.sqlite
```

For development, allow local project cache:

```sh
nearest-exit scan --cache-dir ./data/cache
```

Cache rules:

- Metadata TTL default: 24 hours.
- Probe results should not be reused for live ranking unless explicitly requested.
- History can inform "usual best" later, but fresh measurement should be default.

## VPN Detection

Keep and improve the existing Mullvad pinger's VPN-route warning.

Why:

- If the default route is already inside a VPN tunnel, the scan measures from the VPN exit, not the user's physical/current ISP route.
- This can make most relays appear unreachable or misleadingly far.

macOS checks:

- `route -n get default`
- interface matches `utun`, `tun`, `tap`, `ppp`, `wg`
- gateway in private or CGNAT ranges

Linux checks:

- `ip route show default`
- interface matches `tun`, `tap`, `wg`, `ppp`

CLI behavior:

- Warn by default.
- Add `--ignore-vpn-route-warning`.
- Add `nearest-exit doctor` for diagnostics.

## CLI Commands

### `scan`

Rank relays.

```sh
nearest-exit scan --provider all --country de --top 10
```

Options:

- provider selection
- filters
- probe settings
- output format

### `list`

Show normalized provider relays without probing.

```sh
nearest-exit list --provider nordvpn --country us
```

Useful for debugging discovery.

### `explain`

Explain one result or server.

```sh
nearest-exit explain --provider mullvad --server de-fra-wg-401
```

### `doctor`

Show local network and tool diagnostics.

```sh
nearest-exit doctor
```

Output:

- OS
- Python version
- ping command availability
- default route
- apparent VPN tunnel
- DNS resolution
- cache location

### `compare`

Run multi-provider scan with multiple rounds.

```sh
nearest-exit compare --providers mullvad,nordvpn --country nl --rounds 5
```

## Implementation Phases

### Phase 0: Repository Setup

Tasks:

- Create package skeleton.
- Add `pyproject.toml`.
- Add `README.md`.
- Add formatter/linter config if desired.
- Add initial tests.

Acceptance criteria:

- `python -m nearest_exit.cli --help` works.
- `pip install -e .` exposes `nearest-exit`.
- Tests run.

### Phase 1: Extract Existing Mullvad Logic

Tasks:

- Move Mullvad fetch/cache logic into provider adapter.
- Move ping logic into probe module.
- Add normalized relay model.
- Add scan pipeline.
- Preserve current Mullvad CLI capabilities under new option names.

Acceptance criteria:

- `nearest-exit scan --provider mullvad --country se --top 5` works.
- Output matches or improves current Mullvad pinger behavior.
- No provider-specific logic leaks into scoring.

### Phase 2: Add NordVPN Discovery

Tasks:

- Identify reliable unauthenticated NordVPN metadata source.
- Save sample metadata fixtures in tests.
- Implement `NordVPNProvider`.
- Normalize country, city, hostname, IP, load, and technology fields.
- Add provider notes documenting endpoint behavior and assumptions.

Acceptance criteria:

- `nearest-exit list --provider nordvpn --country us` returns real candidates.
- `nearest-exit scan --provider nordvpn --country us --top 5` ranks candidates.
- If metadata source fails, errors are clear and actionable.

### Phase 3: Unified Ranking

Tasks:

- Implement scoring formula.
- Add reason strings.
- Add stable table output.
- Add JSON output.
- Add sorting tests.

Acceptance criteria:

- Failed relays sort below reachable relays.
- Lower loss beats small RTT differences.
- Ties are deterministic.
- `--json` output includes raw score components.

### Phase 4: Diagnostics

Tasks:

- Implement `doctor`.
- Add VPN-route warning.
- Add DNS check.
- Add ping availability check.

Acceptance criteria:

- User can understand when results are distorted by an active VPN.
- Tool fails gracefully when `ping` is missing or blocked.

### Phase 5: Multi-Round Measurement

Tasks:

- Add `--rounds`.
- Compute median RTT, jitter, loss.
- Add round delay.
- Add result summary.

Acceptance criteria:

- Top results are less noisy than single-shot scans.
- JSON contains per-round samples.

### Phase 6: History

Tasks:

- Add SQLite history.
- Store scan timestamp, network fingerprint, provider, relay, metrics.
- Add `history best` command.

Acceptance criteria:

- User can see which relays usually perform best on a known network.
- Fresh scan remains the default recommendation.

## Testing Strategy

Unit tests:

- Normalize Mullvad relay fixture.
- Normalize NordVPN relay fixture.
- Score successful vs failed probes.
- Score loss vs latency tradeoff.
- Parse macOS ping output.
- Parse Linux ping output.
- Validate CLI arguments.

Integration tests:

- Run provider adapter against recorded metadata.
- Run ICMP probe against `127.0.0.1`.
- Run scan pipeline with fake provider and fake probe.

Avoid live provider API calls in default tests.

Use live tests only behind an explicit flag:

```sh
NEAREST_EXIT_LIVE=1 pytest
```

## Security And Safety

Rules:

- Never build shell commands with string concatenation.
- Never run provider-provided values through a shell.
- Never store provider credentials in V1.
- Keep scan concurrency bounded.
- Avoid aggressive probing defaults.
- Respect provider infrastructure by caching metadata and limiting probe count.

Potential risks:

- High concurrency can look noisy to networks.
- ICMP scans may be rate-limited.
- Provider metadata endpoints may change.
- Some networks block ping.

Mitigations:

- Default concurrency cap.
- Clear timeout.
- Provider metadata caching.
- `doctor` command.
- Good error messages.

## UX Details

Default scan should be useful with no flags:

```sh
nearest-exit scan
```

Default behavior:

- Provider: all configured public providers.
- Top: 10.
- Count: 3.
- Rounds: 1.
- Progress: on for TTY, off for non-TTY.
- Output: table.

Table columns:

- rank
- provider
- server
- country
- city
- protocol
- IP
- score
- RTT
- loss
- jitter

Use stderr for:

- progress
- warnings
- diagnostics

Use stdout for:

- final table
- JSON
- CSV

## Comparison Against Existing Scripts

`nordPing` gives one useful idea:

- Numeric hostname probing can find reachable NordVPN hosts even when no metadata source is available.

But it should not be the main design because:

- It guesses server ranges.
- It has no city or load awareness.
- It can miss valid servers outside the selected range.
- It can spend time probing nonexistent hosts.
- It uses shell string commands.
- It can fail on no-response output.

The existing Mullvad pinger gives stronger building blocks:

- Provider metadata first.
- Async probing.
- Cache.
- Filters.
- VPN-route warning.
- Package metadata.

Nearest Exit should evolve from the Mullvad pinger architecture and add NordVPN through a clean provider adapter.

## Research From Other Tools

The GitHub ecosystem already has several small VPN server-selection tools. The useful ideas are mostly around discovery, filtering, and operational convenience. The parts to avoid are shell-heavy parsing, stale hostname guessing, and tight coupling to one provider's transient API shape.

### `mrzool/nordvpn-server-find`

Repository:

- https://github.com/mrzool/nordvpn-server-find

What it does:

- Shell script.
- Uses NordVPN server load data.
- Supports country filtering.
- Supports max load threshold.
- Supports a quiet mode that prints only the best hostname.
- Has a `recommended` mode for scripting with third-party VPN clients.

Code observations:

- It calls `https://nordvpn.com/api/server/stats` for load data.
- It previously used `https://nordvpn.com/wp-admin/admin-ajax.php?action=servers_recommendations` for recommended server output.
- It uses `jq` heavily.
- It validates ISO country codes locally.
- It supports terminal-aware output, stripping color when stdout is not a TTY.

Ideas to take:

- Add `--quiet` or `--best-only` for scripts.
- Add `--recommended-provider` only as a comparison signal, not as ground truth.
- Add country-code validation with friendly errors.
- Keep terminal output clean and remove color automatically when not writing to a TTY.
- Support third-party client scripting by printing a bare hostname, IP, or config identifier.

Ideas to avoid:

- Do not depend on the old WordPress admin-ajax recommendation endpoint. When checked on May 1, 2026, it returned a Cloudflare browser challenge from this environment.
- Do not make `jq` a runtime dependency.
- Do not rank by provider-reported load alone.

### `trishmapow/nordvpn-tools`

Repository:

- https://github.com/trishmapow/nordvpn-tools

What it does:

- Python script.
- Uses NordVPN `/v1/servers/countries` to map country code to country ID.
- Uses NordVPN `/v1/servers/recommendations` for server details.
- Filters by city and max load.
- Optionally runs `fping` on Linux to show average ping.
- Prints a table with name, load, IP, groups, and ping.

Code observations:

- The endpoint can return useful fields such as server name, station IP, load, groups, country code, and city name.
- It asks the recommendations endpoint for selected fields to reduce response size.
- It treats `fping` as optional and Linux-only.
- It uses `tabulate` for readable tables.

Ideas to take:

- Use NordVPN `/v1/servers/recommendations` as the first NordVPN discovery source.
- Query only needed fields when possible.
- Support city filters for NordVPN.
- Treat provider load as a ranking feature, not as the ranking.
- Consider optional `fping` acceleration later for Linux users scanning large sets.

Ideas to avoid:

- Do not require Linux-only `fping` for core behavior.
- Do not couple output formatting to a third-party table library in V1.
- Do not assume the exact field set stays stable; save fixtures and test normalization.

Current verification:

- `https://api.nordvpn.com/v1/servers/recommendations?limit=1` returned rich JSON from this environment on May 1, 2026.
- The sample included `hostname`, `station`, `load`, `status`, `locations`, `services`, `technologies`, `groups`, and WireGuard public-key metadata.

### `malgr/NordVPN-Server-Lister`

Repository:

- https://github.com/malgr/NordVPN-Server-Lister

What it does:

- Small Python script.
- Calls `https://api.nordvpn.com/server`.
- Filters by country flag, max load, and proxy/SOCKS feature flags.

Ideas to take:

- Preserve proxy-related metadata where provider APIs expose it.
- Add a normalized feature model for provider-specific capabilities:
  - OpenVPN TCP
  - OpenVPN UDP
  - WireGuard
  - SOCKS
  - HTTP proxy
  - P2P
  - Double VPN / multihop
  - Tor-over-VPN
  - Port forwarding

Ideas to avoid:

- Do not use this older endpoint as the primary NordVPN source unless the newer endpoint fails.
- Do not write single-file scripts with parsing and filtering at module import time.

Current verification:

- `https://api.nordvpn.com/server` returned HTTP 403 from this environment on May 1, 2026.
- Treat it as a fallback or historical endpoint, not as the first choice.

### `openpyn-nordvpn`

Repository/site:

- https://jotygill.github.io/openpyn-nordvpn/

What it does:

- Full NordVPN OpenVPN manager.
- Uses NordVPN API data.
- Caches NordVPN JSON.
- Filters by country, area, P2P, dedicated IP, double VPN, Onion over VPN, obfuscated servers, Netflix-oriented hardcoded server ranges, and protocol.
- Connects via OpenVPN and includes Linux firewall/DNS handling.

Ideas to take:

- Add provider capability filters beyond country and city.
- Cache NordVPN metadata with short TTL and graceful fallback to stale cache.
- Add a "feature profile" abstraction:
  - `standard`
  - `p2p`
  - `obfuscated`
  - `double-vpn`
  - `tor`
  - `proxy`
  - `wireguard`
  - `openvpn-udp`
  - `openvpn-tcp`
- Consider skipping suspiciously low provider load values if practical evidence shows they often correspond to broken or newly rotated servers. Openpyn has a rule that skips NordVPN servers with load below 6 in one path; we should not copy that blindly, but it is worth testing.

Ideas to avoid:

- Do not include streaming-service-specific hardcoded server ranges in core ranking.
- Do not become a VPN connection manager in V1.
- Do not mix firewall, DNS, and server ranking logic.

### `grant0417/mullvad-ping`

Repository:

- https://github.com/grant0417/mullvad-ping

What it does:

- Deno/TypeScript CLI.
- Uses Mullvad relay API by relay type.
- Supports listing countries, cities, providers, and servers.
- Filters by country, city code, server type, port speed, provider, ownership, run mode, and inactive status.
- Parses min/avg/max/mdev from ping output.
- Supports JSON output.
- Uses interactive spinners and clean table formatting.

Ideas to take:

- Add `list countries`, `list cities`, and `list providers`.
- Add run-mode filters for providers that expose RAM/disk boot mode.
- Preserve min/max/mdev or equivalent jitter data instead of only average RTT.
- Support `--top 0` or `--limit -1` for all results, but choose one convention.
- Make JSON output include full normalized relay metadata plus probe metrics.

Ideas to avoid:

- Do not ping servers serially for the main scan path. Keep async concurrency.
- Avoid Unicode table separators in default output unless the project intentionally permits non-ASCII output.

### `ip-address-list/nordvpn`

Repository:

- https://github.com/ip-address-list/nordvpn

What it does:

- Publishes refreshed NordVPN HTTPS proxy server lists.

Ideas to take:

- Treat third-party generated IP lists as optional fallback sources only.
- Add source quality levels:
  - `official-live`
  - `official-cached`
  - `community-live`
  - `community-cached`
  - `dns-derived`
  - `manual`

Ideas to avoid:

- Do not rank or recommend from a third-party list unless the source is explicit in output.
- Do not mix proxy-only IPs with VPN relay IPs without labeling them.

### Gluetun

Repository:

- https://github.com/qdm12/gluetun

Why it matters:

- Gluetun is not a pinger, but it has broad provider integration and a mature cross-provider server model.
- It supports many providers, including AirVPN, IVPN, Mullvad, NordVPN, Private Internet Access, ProtonVPN, Surfshark, and Windscribe.
- Its documented server-selection model includes fields such as VPN protocol, country, region, city, ISP, hostname, categories, TCP/UDP support, WireGuard public key, ownership, free/premium, streaming, multihop, port forwarding, secure core, Tor, and IP addresses.

Ideas to take:

- Use a broad normalized server model from the beginning, even if V1 only fills a subset.
- Separate provider update code from provider selection code.
- Add feature flags as first-class fields instead of provider-specific ad hoc booleans.
- Consider importing or comparing against Gluetun's server data later as a community/provider fallback.

Ideas to avoid:

- Do not copy Gluetun's connection-management scope. Nearest Exit should remain a measurement and recommendation tool first.

## Provider Backlog

Providers should be prioritized by how public, structured, and stable their server metadata is. A provider with good public metadata should be easy to add. A provider that requires authenticated config downloads or scraping should be lower priority.

### Tier 1: Strong Candidates For Early Support

#### Mullvad

Source:

- `https://api.mullvad.net/www/relays/all/`

Status:

- Verified reachable from this environment on May 1, 2026.
- Returns structured JSON.

Useful fields:

- hostname
- country code/name
- city code/name
- active state
- ownership
- provider
- entry IPv4/IPv6
- network port speed
- server type
- run mode/boot metadata
- SOCKS metadata

Implementation priority:

- First provider because the existing local pinger already uses it.

#### NordVPN

Primary source:

- `https://api.nordvpn.com/v1/servers/recommendations`

Secondary/historical sources:

- `https://api.nordvpn.com/v1/servers/countries`
- `https://api.nordvpn.com/server`
- `https://nordvpn.com/api/server/stats`

Status:

- `/v1/servers/recommendations?limit=1` was verified reachable from this environment on May 1, 2026.
- `api.nordvpn.com/server` returned HTTP 403 from this environment on May 1, 2026.
- The old `nordvpn.com/wp-admin/admin-ajax.php?action=servers_recommendations` endpoint returned a Cloudflare browser challenge from this environment on May 1, 2026.

Useful fields from the verified recommendations endpoint:

- hostname
- station IP
- load
- online status
- country/city/coordinates
- services
- technologies
- groups/categories
- WireGuard public key metadata
- entry IPs

Implementation priority:

- Second provider.

Important design point:

- NordVPN has multiple related endpoints, and at least some are protected or deprecated. The adapter must support endpoint versioning and fixture tests.

#### AirVPN

Source:

- `https://airvpn.org/api/status/?format=json`

Documentation:

- https://airvpn.org/faq/api/

Status:

- Verified reachable from this environment on May 1, 2026.
- AirVPN documents `status` as a free API service.
- API docs mention a rate limit of 600 requests per 10 minutes.

Useful fields:

- server public name
- country name/code
- location
- continent
- bandwidth used
- max bandwidth
- users
- current load
- health
- warnings
- multiple IPv4 and IPv6 entry addresses
- recommended/best server at country/continent/planet levels

Implementation priority:

- Third provider. It is unusually transparent and has a strong public status API.

Special handling:

- A single AirVPN logical server exposes multiple entry addresses. Model these as either multiple relay targets under one logical relay or as separate probe targets attached to one relay.
- Health warnings should affect score strongly.

#### Private Internet Access

Source:

- `https://serverlist.piaservers.net/vpninfo/servers/v6`

Status:

- Verified reachable from this environment on May 1, 2026.
- Returns JSON followed by an RSA signature block.
- The JSON must be parsed by extracting the JSON object before the signature tail.

Useful fields:

- protocol groups and ports
- regions
- region ID/name/country
- DNS name
- port forwarding support
- SOCKS5 proxy group
- geo/virtual location flag
- offline flag
- servers by protocol group
- per-server IP and common name

Implementation priority:

- Fourth provider.

Special handling:

- Normalize region-level data and protocol-specific server IPs.
- Preserve `port_forward`, `geo`, and `offline`.
- Do not treat the signature block as parse failure; strip it deliberately and optionally verify it later.
- Include `proxysocks` endpoints in SOCKS5 scans.

### Tier 2: Good Candidates, Needs More Research

#### ExpressVPN

Public sources:

- Location/protocol availability page: https://www.expressvpn.com/vpn-server
- Manual configuration docs: https://www.expressvpn.com/support/manage-account/find-manual-configuration-credentials/

Current notes:

- ExpressVPN publishes a public location and protocol availability matrix.
- ExpressVPN documents that manual configuration requires signing in to the setup page.
- ExpressVPN documents that users can download OpenVPN configuration files after account verification.
- ExpressVPN documents that not all app locations may be available for manually configured connections.
- The public page is useful for availability, but it is not a clean unauthenticated per-server IP list.

Implementation priority:

- Add as a Tier 2 import/provider-research target, not as an early official-live adapter.

Likely adapter modes:

1. `expressvpn-locations`: public location/protocol list only; useful for showing availability, not enough for direct probing unless hostnames are discoverable.
2. `expressvpn-ovpn-import`: user supplies downloaded `.ovpn` files; Nearest Exit extracts `remote` hostnames/IPs and probes them.
3. `expressvpn-manual-dir`: user points to a directory of manual config files.

CLI examples:

```sh
nearest-exit import-ovpn --provider expressvpn ~/Downloads/expressvpn-configs
nearest-exit scan --provider expressvpn --source manual-config
nearest-exit list --provider expressvpn --source public-locations
```

Special handling:

- Mark imported ExpressVPN targets as `manual` or `user-config`, not `official-live`.
- Preserve protocol availability from the public page where available.
- Do not attempt authenticated scraping of the user's ExpressVPN account in V1.
- Lightway support should be represented as metadata, but probing Lightway directly is out of scope unless a safe public handshake method exists.

#### Proton VPN

Public source possibilities:

- Official server-list page: https://protonvpn.com/vpn-servers
- App/API behavior needs research.

Current notes:

- Proton publicly documents server locations and server counts.
- Proton has very large fleet data and has introduced streamlined server lists in apps, meaning an unauthenticated full per-server list may be intentionally limited.

Implementation priority:

- Add after Tier 1 unless a reliable unauthenticated metadata endpoint is found.

Likely useful fields if available:

- country
- city
- load
- free/paid tier
- Secure Core
- P2P
- Tor
- streaming
- port forwarding
- WireGuard/OpenVPN support

#### IVPN

Why include:

- Strong privacy-oriented provider.
- Gluetun supports IVPN and documents WireGuard port options.

Research needed:

- Find official or app-consumed server list source.
- Determine whether IPs and protocol ports are public without login.

#### Surfshark

Why include:

- Large mainstream provider.
- Gluetun supports Surfshark.

Research needed:

- Find official or app-consumed server list source.
- Determine whether server IPs are exposed or only hostnames/configs.

#### Windscribe

Why include:

- Public location list and status-oriented pages exist.
- Gluetun supports Windscribe, including WireGuard.

Research needed:

- Find a structured unauthenticated server/status endpoint.
- Determine if per-server IPs are public or only location-level names are public.

#### Perfect Privacy

Why include:

- Often exposes detailed server status publicly.
- Good candidate for load-aware ranking if public status data is structured.

Research needed:

- Verify current status endpoint and fields.

### Tier 3: Possible But Lower Priority

- CyberGhost
- IPVanish
- PrivadoVPN
- PrivateVPN
- PureVPN
- TorGuard
- VyprVPN
- VPN Unlimited

Reasons for lower priority:

- Public server data may be less structured.
- Some may require authenticated config downloads.
- Some may publish only country/location lists, not per-server probe targets.
- Some may use broad DNS names that rotate behind provider load balancing.

These can still be supported through a `dns-derived` adapter if the user provides hostnames or config files.

## Source Quality Model

Every relay should carry source metadata:

```python
class SourceQuality(StrEnum):
    OFFICIAL_LIVE = "official-live"
    OFFICIAL_CACHED = "official-cached"
    COMMUNITY_LIVE = "community-live"
    COMMUNITY_CACHED = "community-cached"
    DNS_DERIVED = "dns-derived"
    MANUAL = "manual"
```

The output should expose this:

```text
rank provider  server      source          score  rtt
1    airvpn    Adhil       official-live   96.8   18.2ms
2    nordvpn   de1045      official-live   95.1   19.7ms
3    pia       de-frankfurt official-live  93.4   21.0ms
```

Why this matters:

- It keeps third-party IP lists honest.
- It helps debug provider endpoint failures.
- It allows conservative defaults while still letting power users opt into fallback sources.

## Provider Capability Model

Add normalized provider capability flags:

```python
@dataclass(frozen=True)
class RelayFeatures:
    wireguard: bool = False
    openvpn_udp: bool = False
    openvpn_tcp: bool = False
    ikev2: bool = False
    socks5: bool = False
    http_proxy: bool = False
    shadowsocks: bool = False
    p2p: bool = False
    obfuscated: bool = False
    double_vpn: bool = False
    tor_over_vpn: bool = False
    port_forwarding: bool = False
    secure_core: bool = False
    streaming: bool = False
    free_tier: bool = False
    paid_tier: bool = False
    owned: bool | None = None
    virtual_location: bool | None = None
```

This avoids turning the CLI into provider-specific flag soup.

The CLI can expose common filters:

```sh
nearest-exit scan --feature wireguard
nearest-exit scan --feature p2p
nearest-exit scan --feature port-forwarding
nearest-exit scan --feature socks5
nearest-exit scan --no-virtual
```

Provider-specific aliases can map into these features:

```sh
nearest-exit scan --provider nordvpn --category p2p
nearest-exit scan --provider airvpn --health ok
nearest-exit scan --provider pia --port-forwarding
```

## Updated Provider Implementation Order

Recommended order now:

1. Mullvad adapter.
2. NordVPN adapter using `/v1/servers/recommendations`.
3. AirVPN adapter using public `status` API.
4. PIA adapter using `serverlist.piaservers.net/vpninfo/servers/v6`.
5. SOCKS5 probe and SOCKS-aware output for Mullvad, NordVPN, and PIA.
6. Gluetun import/fallback adapter.
7. ExpressVPN `.ovpn` import adapter.
8. Proton VPN research adapter.
9. IVPN/Surfshark/Windscribe research adapters.

Why this order:

- Mullvad is already mostly implemented locally.
- NordVPN is the original motivation and has a verified rich endpoint.
- AirVPN has high-quality public status data.
- PIA has a public server list with protocol/port detail.
- SOCKS5 is useful for compatibility and should be modeled before provider count grows.
- ExpressVPN is useful, but likely starts as user-supplied config import rather than official-live discovery.
- Gluetun can broaden provider coverage without pretending every provider has equal source quality.

## Updated NordVPN Adapter Plan

The NordVPN adapter should not use `nordPing` hostname ranges except as an explicit fallback.

Discovery sequence:

1. Fetch country list from `/v1/servers/countries` when a country code needs mapping.
2. Fetch recommendations from `/v1/servers/recommendations`.
3. Request fields for:
   - name
   - hostname
   - station
   - load
   - status
   - locations
   - services
   - technologies
   - groups
   - ips
4. Normalize into `Relay`.
5. Preserve raw technology identifiers.
6. Extract WireGuard public key if present.
7. Extract proxy hostname metadata if present.

Fallback sequence:

1. Try cached recommendations.
2. Try older endpoint only if currently reachable.
3. Try DNS/hostname range scan only when the user explicitly passes `--nordvpn-range`.

CLI additions:

```sh
nearest-exit list --provider nordvpn --country ae
nearest-exit scan --provider nordvpn --country ae --feature wireguard --max-load 50
nearest-exit scan --provider nordvpn --city Dubai --top 5
nearest-exit scan --provider nordvpn --nordvpn-range us:9000-9500
```

## Updated AirVPN Adapter Plan

Discovery:

1. Fetch `https://airvpn.org/api/status/?format=json`.
2. Read `servers`.
3. Ignore country/continent/planet aggregate records for relay ranking, but keep their `server_best` fields for provider recommendation comparison.
4. For each server:
   - create one logical relay
   - create probe targets for `ip_v4_in1..ip_v4_in4`
   - optionally create IPv6 probe targets for `ip_v6_in1..ip_v6_in4`
5. Treat `health != ok` as degraded.
6. Treat `currentload`, `bw`, `bw_max`, and `users` as score inputs.

CLI additions:

```sh
nearest-exit scan --provider airvpn --country de
nearest-exit scan --provider airvpn --health ok
nearest-exit explain --provider airvpn --server Adhil
```

Special score rules:

- Error health should sort below healthy relays unless the user passes `--include-unhealthy`.
- Warning health should be penalized.
- Multiple entry IPs should be probed independently and the best stable target should represent the relay, while the output still exposes all targets.

## Updated PIA Adapter Plan

Discovery:

1. Fetch `https://serverlist.piaservers.net/vpninfo/servers/v6`.
2. Strip signature tail by finding the end of the first JSON object.
3. Parse `groups` for protocol-to-port mapping.
4. Parse `regions`.
5. For each region, create relays for each protocol group and server IP.
6. Preserve:
   - region ID
   - region name
   - country
   - DNS name
   - port forwarding support
   - `geo` flag
   - `offline` flag
   - protocol group
   - ports

CLI additions:

```sh
nearest-exit scan --provider pia --country us
nearest-exit scan --provider pia --feature wireguard
nearest-exit scan --provider pia --feature socks5
nearest-exit scan --provider pia --port-forwarding
nearest-exit scan --provider pia --no-virtual
```

Special parser test:

- Add a fixture with a signature block after JSON and verify parsing does not fail.

## Updated ExpressVPN Import Plan

ExpressVPN should be supported through imported manual configuration files first.

Discovery:

1. User downloads OpenVPN configs from their ExpressVPN setup page.
2. User runs `nearest-exit import-ovpn --provider expressvpn <path>`.
3. Parser reads each `.ovpn` file.
4. Parser extracts:
   - `remote` hostnames/IPs
   - ports
   - protocol hints
   - config display name from filename
   - optional country/city tokens from filename
5. Imported targets are stored as `manual` source quality.
6. Scan probes the extracted remotes.

CLI additions:

```sh
nearest-exit import-ovpn --provider expressvpn ~/Downloads/expressvpn-configs
nearest-exit scan --provider expressvpn --source manual
nearest-exit list --provider expressvpn --source manual
```

Rules:

- Never ask for ExpressVPN account credentials.
- Never scrape the authenticated setup page in V1.
- Public location/protocol availability can be shown as reference, but imported config targets are required for probing.
- If ExpressVPN later exposes a clean public endpoint, add it as `official-live`.

## Updated Gluetun Fallback Plan

Gluetun should be treated as an optional interoperability source, not a runtime dependency.

Possible modes:

```sh
nearest-exit import-gluetun --servers-json /path/to/servers.json
nearest-exit scan --source gluetun --provider surfshark
nearest-exit list --source gluetun --provider protonvpn
```

Use cases:

- Provider does not have a public live endpoint.
- User already runs Gluetun and has an updated `servers.json`.
- We want a sanity comparison against a mature provider model.

Rules:

- Mark imported relays as `community-cached` or `user-cached`, depending on origin.
- Do not silently mix imported Gluetun data with official live provider data.
- Show source in output.

## Config File

Location: `~/.config/nearest-exit/config.toml` (XDG-respecting, override with `NEAREST_EXIT_CONFIG`).

Example:

```toml
[providers]
order = ["nordvpn", "airvpn", "mullvad"]
weights = { nordvpn = 1.0, airvpn = 0.9, mullvad = 0.7 }
others_allowed = true
others_threshold = 0.15

[defaults]
feature = "wireguard"
scope = "nearby"          # here | nearby | region | global
top = 3
rounds = 1

[geo]
lookup = "ipinfo"         # ipinfo | ipapi | none
speedtest_calibration = false   # opt-in V2 signal

[history]
enabled = true
path = "~/.local/share/nearest-exit/history.sqlite"
```

`nearest-exit prefs init` should write this file with the defaults above on first run if it does not exist.

## Network Fingerprint

A "network" for history and preference-learning is identified by the tuple `(public_ip_asn, default_gateway_mac_or_ssid_hash)`. The MAC/SSID part lets the tool distinguish home Wi-Fi from cafe Wi-Fi on the same ISP. Hash both parts so the history DB never stores raw network identifiers.

## Open Questions

- Which NordVPN metadata source is reliable enough today?
- Should the first public release include NordVPN if discovery is unstable?
- Should the score include provider-reported load from day one?
- Should geographic distance be shown as context if relay coordinates are available?
- Should we add a "fastest country near me" mode that groups by country?
- Should we support IPv6 probing?
- Should we keep the old `mullvad-server-ping` CLI as a compatibility shim?
- Should provider recommendations be shown in output as "provider would choose X" next to "Nearest Exit measured Y"?
- Should Nearest Exit have a `--source-quality official-live` default that excludes community and DNS-derived sources unless explicitly enabled?

## First Concrete Build Steps

1. Create Python package skeleton.
2. Port `Relay`, `ProbeResult`, and `RankedRelay` models.
3. Move Mullvad API fetch into `providers/mullvad.py`.
4. Move ICMP subprocess logic into `probes/icmp.py`.
5. Implement fake provider and fake probe tests.
6. Implement `scan --provider mullvad`.
7. Add JSON output.
8. Add `doctor`.
9. Implement `providers/nordvpn.py` against `/v1/servers/recommendations`.
10. Add NordVPN fixtures from the verified response shape.
11. Implement `providers/airvpn.py`.
12. Implement `providers/pia.py`, including signature-tail stripping.
13. Implement SOCKS5 probe support.
14. Add SOCKS5 normalization for Mullvad, NordVPN, and PIA.
15. Add `list countries`, `list cities`, `list providers`, and `list features`.
16. Add source-quality labels to every relay.
17. Add ExpressVPN `.ovpn` import mode.

## Definition Of Done For The First Useful Version

The first useful version is done when this works:

```sh
nearest-exit scan --provider mullvad --top 10
nearest-exit scan --provider nordvpn --top 10
nearest-exit scan --provider airvpn --top 10
nearest-exit scan --provider pia --top 10
nearest-exit scan --feature socks5 --top 10
nearest-exit import-ovpn --provider expressvpn ~/Downloads/expressvpn-configs
nearest-exit scan --provider expressvpn --source manual --top 10
nearest-exit scan --provider all --country de --top 20 --json
nearest-exit doctor
```

And these are true:

- Results are ranked by measured local latency.
- Unreachable relays do not crash the scan.
- Provider metadata is cached.
- VPN-route warning exists.
- Output is human-readable and machine-readable.
- Tests cover scoring and provider normalization.

## Additional Research (Round 2)

The following ideas came out of a deeper survey beyond the initial tool list. Tag each as **adopt now**, **adopt V2+**, or **anti-pattern to avoid**.

### Measurement techniques

- **adopt now — TCP/443 fallback when ICMP fails.** Many provider relays null-route ICMP. If ICMP returns no samples for a relay, fall back to a single TCP-SYN-then-close to `:443`. Universal answer surface, no protocol assumptions.
- **adopt V2 — real WireGuard handshake initiation packet.** A 148-byte WG handshake-init UDP packet is fixed-format and can be timed against the relay's actual WG port. Reflects real reachability where ICMP lies. See `cloudflare/boringtun` for handshake construction. Use only when relay metadata exposes a WG public key (Mullvad, NordVPN, AirVPN do).
- **adopt V2 — TLS ClientHello to OpenVPN port** for OpenVPN-only relays. More truthful than TCP-SYN.
- **adopt now — discard the first probe per relay.** Cold ARP/route resolution skews the first sample. Ookla, Cloudflare, and LibreSpeed all do this. Take min/median of remaining samples.
- **adopt now — resolve hostnames once, probe IPs.** A user's DNS may be hijacked, geo-skewed, or run inside a captive portal. Resolve relay hostnames via DoH (Cloudflare 1.1.1.1 or Google) on first fetch, cache the IP with the relay record, then probe by IP.
- **adopt V2 — small-payload HTTPS latency phase**, LibreSpeed-style: 10× 32-byte GETs to a relay's public HTTPS endpoint where one exists. Robust against ICMP rate-limiting.

### Selection algorithms (small probe budget)

- **adopt now — two-stage filter.** Geofilter to top-K candidates by haversine first, *then* probe. ProtonVPN-CLI does this; we should too because Mullvad/Nord have 700–6000 relays and full-sweeps are minutes long.
- **adopt now — sticky preference / hysteresis.** A relay that won yesterday gets a small RTT bonus today (e.g. −3 ms) so the recommendation doesn't flap on noise. Anti-flap, not stuck.
- **adopt V2 — UCB / Thompson sampling on repeat runs.** Instead of probing the same top-10 forever, occasionally re-probe stale-but-once-good relays so the recommendation set doesn't ossify.
- **adopt V3 — Vivaldi network coordinates / iPlane-style anchor prediction.** Probe 5–10 well-chosen anchors per provider; predict latency to the rest from coordinates. At scale this is the only honest answer to "rank 6000 NordVPN relays cheaply."
- **adopt now — Tail-at-Scale hedged probes for the top.** For the final top-3 contenders, send 2 probes in parallel, take first reply. Cheap, reduces tie-break noise.

### Provider feeds we missed

- **adopt now — VPN Gate.** `https://www.vpngate.net/api/iphone/` returns a public CSV with already-measured Ping, Speed, Score, Uptime, lat/long, country, sessions. Free, volunteer-run servers — useful as a low-priority tier and as a *prior* for probe ordering. Source-quality should be `community-live`.
- **adopt now — PIA's meta endpoint pattern.** `pia-foss/manual-connections` shows their official picker queries a meta endpoint that already returns load + lat/long; that's a single-shot prior even before our probes.
- **adopt V2 — mullvadvpn-app's Rust `mullvad-relay-selector` crate.** Their constraint DSL (`location/provider/ownership/protocol`) is a strong inspiration for our `--filter` syntax. Consider mirroring it so power users can write `nearest-exit --in 'eu,!us-owned,wg-only'`.
- **adopt V3 — NetworkManager's relay schema.** Our normalized `Relay` should be close enough to NM's that configs round-trip cleanly, since users may want to feed Nearest Exit's pick into a NetworkManager profile.

### Geo / context

- **adopt now — invalidate geo cache on default-route change.** macOS `route monitor`, Linux `ip monitor`. Network-fingerprint history is wrong without this. Cheap to detect.
- **adopt V2 — M-Lab NDT7 "locate API" pattern.** Ask a meta-service for top-4 nearest candidates, probe those. We can implement our own meta-service later, but the pattern is the right one for cross-provider geo.
- **adopt V2 — AS-path divergence as tiebreaker.** When two relays tie, run `mtr`/`trippy`-style traceroute and check whether the last two hops are shared. If yes, ranking between them is meaningless; if no, the slower one is genuinely a different route worth keeping as backup.

### Anti-patterns to call out in README

- ICMP-only ranking (silently demotes relays that null-route ICMP).
- Full sequential sweeps of every relay (minutes, wasteful, looks abusive).
- Trusting provider-published `load %` as a primary signal — stale and gameable. Tiebreaker only.
- DNS-based hostname pings without controlled resolution (current resolver may be hijacked / geo-skewed).
- Caching probe results across network changes without invalidating on SSID / default-gw / public-IP change.
- Drifting into a connection manager. Stay a measurement and recommendation tool.

### Things we explicitly do NOT want

- VPN Gate CSV's "Speed" / "Score" as ranking inputs — they're measured from Japan and meaningless from elsewhere; use only the volunteer-server *list*, not their measurements.
- Authenticated provider scraping (ExpressVPN account, Proton login). Imported `.ovpn` only.
- Per-protocol throughput estimation in V1. Reachability + latency + jitter is the contract.

## Research Sources

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
- PIA server list endpoint: https://serverlist.piaservers.net/vpninfo/servers/v6
- Mullvad relay API: https://api.mullvad.net/www/relays/all/
- Proton VPN public server page: https://protonvpn.com/vpn-servers
- ExpressVPN public server page: https://www.expressvpn.com/vpn-server
- ExpressVPN manual configuration docs: https://www.expressvpn.com/support/manage-account/find-manual-configuration-credentials/
- VPN Gate public CSV: https://www.vpngate.net/api/iphone/
- PIA manual-connections (meta endpoint pattern): https://github.com/pia-foss/manual-connections
- mullvadvpn-app relay selector (Rust): https://github.com/mullvad/mullvadvpn-app
- ProtonVPN linux-cli-community (geo+load+tier prefilter): https://github.com/ProtonVPN/linux-cli-community
- cloudflare/boringtun (WireGuard handshake construction): https://github.com/cloudflare/boringtun
- LibreSpeed speedtest-cli (small-payload latency phase): https://github.com/librespeed/speedtest-cli
- cloudflare/speedtest (cold-cache discard pattern): https://github.com/cloudflare/speedtest
- M-Lab NDT7 client (locate API pattern): https://github.com/m-lab/ndt7-client-go
- fujiapple/trippy (AS-path divergence tiebreaker): https://github.com/fujiapple/trippy
- Vivaldi network coordinates (Dabek et al., 2004): https://pdos.csail.mit.edu/papers/vivaldi:sigcomm/
- iPlane Nano (Madhyastha et al., 2009): https://web.eecs.umich.edu/~harshavm/iplane/
- "The Tail at Scale" (Dean & Barroso, 2013): https://research.google/pubs/the-tail-at-scale/
