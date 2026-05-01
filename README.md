# Nearest Exit

Independently rank VPN relays by measured reachability and latency from your current network.

VPN clients sometimes pick a server that is geographically plausible but not actually fastest from your real path. Nearest Exit measures candidate relays directly — it does not trust the provider's recommendation as ground truth.

## Status

Pre-alpha. See [PLAN.md](PLAN.md) for the full design. Code is being built up from a small Mullvad-only ICMP pinger.

## Goals

- One-keystroke default: `nearest-exit` detects your current network, applies your provider preferences, and prints the best exit plus nearby alternatives.
- Multi-provider: Mullvad, NordVPN, AirVPN, PIA first; ExpressVPN/Proton/IVPN/Surfshark/Windscribe as research targets.
- Honest measurement: ICMP plus TCP-connect probes, median RTT, jitter, loss; provider load is a tiebreaker, not the ranking.
- Provider-neutral output. SOCKS5 modeled as a first-class probe.
- No connection management in V1.

## Non-goals (V1)

- Connecting or disconnecting tunnels.
- Storing provider credentials.
- Replacing the provider client.

## License

TBD.
