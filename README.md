# Nearest Exit

Independently rank VPN relays by measured reachability and latency from your current network.

VPN clients sometimes pick a server that is geographically plausible but not actually fastest from your real path. Nearest Exit measures candidate relays directly — it does not trust the provider's recommendation as ground truth.

## Status

Pre-alpha, but no longer Mullvad-only. The current CLI can discover and probe Mullvad, NordVPN, AirVPN, and PIA relays, then rank reachable candidates from the current network. See [PLAN.md](PLAN.md) for the full design and phased roadmap.

Current command surface:

```sh
nearest-exit                         # default recommendation flow
nearest-exit scan --provider mullvad # per-provider ranking
nearest-exit scan --provider nordvpn --country de
nearest-exit doctor
nearest-exit prefs init
nearest-exit history
```

## Goals

- One-keystroke default: `nearest-exit` detects your current network, applies your provider preferences, and prints the best exit plus nearby alternatives.
- Multi-provider: Mullvad, NordVPN, AirVPN, PIA first; ExpressVPN/Proton/IVPN/Surfshark/Windscribe as research targets.
- Honest measurement: ICMP plus TCP-connect fallback, median RTT, jitter, loss; provider load is a small tiebreaker, not the ranking.
- Provider-neutral output. SOCKS5 is planned as a first-class probe.
- No connection management in V1.

## Roadmap Snapshot

- P0: keep docs, package metadata, and the implementation contract aligned.
- P1: stabilize shared scoring, provider preference weights, non-preferred provider thresholds, and explanation text.
- P2: make v0.1 shippable with `scan --provider all`, default JSON output, config validation, and CLI smoke tests.
- P3: deepen measurement with SOCKS5 probes, provider-specific TCP targets, multi-entry probing, and stability scoring.
- P4: improve history, add `explain`, add exports, then consider a local dashboard.

## Non-goals (V1)

- Connecting or disconnecting tunnels.
- Storing provider credentials.
- Replacing the provider client.

## License

MIT.
