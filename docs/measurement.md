# How Nearest Exit measures and ranks

This document is the contract for the numbers the tool prints. Everything here
is implemented in `src/nearest_exit/probes/`, `src/nearest_exit/rounds.py` and
`src/nearest_exit/scoring.py`; the constants quoted are the ones in the code.

## The boundary: measured cost versus effective cost

A relay carries two numbers, and the split between them is the point of the
whole design.

**`measured_cost_ms`** is what this network observed, expressed as milliseconds
of equivalent latency:

```text
measured_cost_ms = median_rtt_ms
                 + LOSS_LINEAR_MS    * p + LOSS_QUADRATIC_MS * p * p
                 + JITTER_WEIGHT     * jitter_ms
```

where `p` is the confidence-discounted loss rate described below, and

```text
LOSS_LINEAR_MS    = 300.0
LOSS_QUADRATIC_MS = 3000.0
JITTER_WEIGHT     = 0.5
LOSS_CONFIDENCE_Z = 1.96
```

Nothing else is in that number, and nothing the provider says about itself is
in the *effective* cost either. In particular provider-reported load is not,
even though it is tempting: load is a figure the provider hands us, not
something observed from here, and `measured_cost_ms` is both what the output
labels "measured" and what the provider-preference threshold compares.
Contaminating it would make the preference machinery compare policy against
policy.

**`effective_cost_ms`** is the number relays are actually sorted by. It is the
measured cost plus the things *you* asked for, and nothing else:

```text
effective_cost_ms = measured_cost_ms
                  + provider_penalty_ms
                  - sticky_history_bonus_ms
```

```text
provider_penalty_ms       # from [providers] penalties_ms, empty by default
sticky_history_bonus_ms   # 3ms per past win here, capped at 8ms, off by default
```

Both numbers are always printed. In the `scan` table they are the `cost` and
`ranked` columns; in the default flow's output they are `= 20.8ms` and, when
they differ, `→ ranked 30.8ms (+10.0)`; in `--json` they are `measured_cost_ms`
and `effective_cost_ms`. **With no config file the two are exactly equal**,
which is what makes "ranked on measurement alone" a statement rather than a
claim with an asterisk.

Provider-reported load is displayed next to each relay and is not in either
number. It was briefly a small ranking term, and that was wrong twice over: it
let a figure the provider supplies about its own server decide the order, in a
tool whose entire premise is not trusting exactly that; and its whole range was
narrower than the spread of a five-packet probe, so it could only ever have
decided cases the measurement already could not separate. Those are reported as
ties instead.

So: **median RTT, loss and jitter are measurement. Provider preference and
history are policy, both off by default. Provider load is neither — it is
information.** `--why` prints the derivation term by term and labels load
explicitly as "shown, not ranked on".

## When the measurement cannot decide

Five packets cannot separate two relays a millisecond apart, and pretending
otherwise is the same class of dishonesty as ranking on provider load. After
ranking, the relays whose *measured* cost lies within the wider of their two
jitters (floor 2ms) of the fastest are treated as tied. If more of them are
tied than were asked for, the output prints `Tied (N)` and lists them instead
of naming a `Best:`, and every tied relay is recorded in history at rank 1
rather than handing the anti-flap bonus to whichever one won a coin flip.

The band is computed on measured cost, not effective cost: the claim is about
what the network could tell us, so a provider preference must not be able to
make two identical measurements look distinguishable.

Sorting is `(reachable, effective_cost_ms, hostname)` — unreachable relays
always sort last, and the hostname tiebreak makes two runs on the same data
produce the same order.

## Why observed loss is discounted

Penalising the loss rate you observed is wrong at the packet counts this tool
can afford. With five packets, one drop is a 20% loss rate; with three packets
it is 33%. Neither is 20% or 33% evidence about the path — it is one packet.
Charging the observed rate directly would let a single unlucky drop, which
happens constantly on a wireless link, reorder the entire table.

So the penalty is applied not to the observed rate but to the **lower bound of
the Wilson score interval** for it at 95% confidence (`LOSS_CONFIDENCE_Z =
1.96`) — roughly, "how much loss are we actually confident about, given how
little we sampled". A single drop becomes a small charge; a relay that keeps
dropping packets across more packets converges on the real rate and is ranked
out.

Observed rate, discounted rate, and the resulting penalty:

| packets | drops | observed | confident | penalty |
|---------|-------|----------|-----------|---------|
| 3       | 1     | 33%      | 6.1%      | 29.8ms  |
| 3       | 2     | 67%      | 20.8%     | 191.7ms |
| 5       | 1     | 20%      | 3.6%      | 14.8ms  |
| 5       | 2     | 40%      | 11.8%     | 76.8ms  |
| 10      | 1     | 10%      | 1.8%      | 6.3ms   |
| 10      | 2     | 20%      | 5.7%      | 26.6ms  |
| 20      | 1     | 5%       | 0.9%      | 2.9ms   |
| 20      | 2     | 10%      | 2.8%      | 10.7ms  |

This is also why the default probe count is 5 rather than 3: it moves a single
drop from a table-reordering ~30ms to a defensible ~15ms.

The penalty itself is superlinear on purpose. The linear term makes any
confident loss matter; the quadratic term makes a badly lossy relay lose
outright rather than trading a few milliseconds against latency. At a
*confident* 5% loss the charge is `300 × 0.05 + 3000 × 0.05² = 22.5ms`, so a
lossy relay has to be more than 22ms faster to still win. Note that the `loss`
column in the output shows the **observed** rate, and `--why` adds a line
saying what it was discounted to.

Jitter counts for half of what the same number of milliseconds of median RTT
would (`JITTER_WEIGHT = 0.5`). It is a real cost for interactive traffic but
should not outrank latency outright.

## The probe ladder

`--probe` chooses *how* to measure. It is a separate axis from `--protocol`,
which chooses *which relays qualify*; conflating the two is why an earlier
version selected the SOCKS5 probe from a relay filter.

`--probe auto` (the default) tries each method until one answers:

1. **ICMP** — the system `ping` binary, invoked as an argument list, never
   through a shell. `ping -c N -W <ms>` on macOS, `ping -c N -W <seconds>` on
   Linux, `ping -n N -w <ms>` elsewhere. Replies are parsed with a regex that
   captures both the sequence number and the time.
2. **TCP connect** — if ICMP produced no reply and `--no-tcp-fallback` was not
   passed. `asyncio.open_connection` to the relay's entry IP on port 443,
   timing the handshake and closing immediately, with no application data.
   Some providers get a better target than 443: PIA's `meta` service endpoint,
   or its `ovpntcp` endpoint when OpenVPN was requested. The TCP fallback sends
   `max(2, count - 1)` attempts rather than the full count, since it is already
   a second attempt at the same relay.

The other values pin one method for the whole table, so every row is measured
the same way and the numbers stay comparable: `--probe icmp` skips the
fallback, `--probe tcp` skips ICMP, and:

3. **`--probe openvpn`** — talks to the relay's OpenVPN control channel
   instead of the IP stack in front of it. This is the only probe here that
   measures the VPN daemon *as a VPN daemon*: a relay can answer ping quickly
   while its OpenVPN process is loaded, throttled, or routed differently.

   The packet is `P_CONTROL_HARD_RESET_CLIENT_V2` — 14 bytes, entirely
   plaintext, no keys and no negotiation:

   ```text
   u8   (opcode 7 << 3) | key_id 0
   u8   session_id[8]        random
   u8   ack_array_len = 0
   u32  packet_id = 0        big-endian
   ```

   PIA answers it outright with a `P_CONTROL_HARD_RESET_SERVER_V2` over UDP —
   verified on 8080 and 853 across every region sampled. AirVPN and NordVPN run
   `tls-auth`/`tls-crypt`, so they never answer an unauthenticated reset, but
   over TCP they *read* it, fail the HMAC and close. Both outcomes are timed
   from the moment the packet goes out, so both are a daemon round trip. The
   preceding TCP connect is deliberately not counted: it completes in the
   kernel before the daemon is ever scheduled, which is the exact thing this
   probe exists to see past. A server that accepts the connection and then
   ignores us never read the packet, so a timeout is a failure rather than a
   slow success.

   Two ports PIA advertises are deliberately not used: `openvpn_udp` lists
   8080, 853, 123 and 53, and the last two are routinely intercepted on the way
   out by local DNS and NTP middleboxes, which measures the middlebox.

   Mullvad has no OpenVPN fleet at all, so `--probe openvpn` finds no target
   there and says so rather than reporting a dead relay.

   **How much does it differ from ICMP?** On this connection, less than the
   theory suggests. Fifteen PIA regions, strictly sequential and
   ABBA-interleaved against the same IP so only the responding plane varies:
   median delta **-1.5ms**, range -8.2 to +7.2ms, and **0 of 14** completed
   regions disagreed by more than 10ms. So ICMP is usually a good proxy. The
   value of the OpenVPN probe is that it lets you check rather than assume,
   on a link where ICMP is deprioritised or rate-limited at the edge.

4. **`--probe ikev2`** — has the relay's IKEv2 daemon refuse an
   unauthenticated proposal, and times the refusal. One 216-byte UDP datagram
   out, 36 bytes back, on the plane IKEv2 actually runs on.

   The request is a fixed-layout `IKE_SA_INIT` (RFC 7296 §3.1) proposing
   **only Diffie-Hellman group 1, MODP-768**, which every current responder
   refuses with `NO_PROPOSAL_CHOSEN`. That is not luck: group 1 is formally
   DEPRECATED by RFC 8247, so refusing it is the specified behaviour rather
   than an observed quirk. All four transform identifiers used here
   (`ENCR_AES_CBC=12`, `PRF_HMAC_SHA1=2`, `AUTH_HMAC_SHA1_96=2`, group 1)
   were checked against the IANA IKEv2 registries rather than from memory. Refusing is the point, and it is better
   than being accepted in three separate ways. An accepted exchange makes the
   responder do a 2048-bit modexp and bakes it into the measured RTT — worth
   +2.7ms on PIA and +6.0ms on NordVPN over the refused variant on the same
   host in the same round, varying with how loaded the relay is, which is
   exactly the noise a latency probe must not add. Three back-to-back samples
   of an accepted exchange trip the RFC 7296 §2.6 cookie machinery; a refused
   one never does, because it creates no half-open SA. And a 36-byte reply to
   a 216-byte request is an amplification ratio of 0.17, so the probe cannot
   be turned into a reflector — measured, 36 bytes on every one of eight live
   NordVPN responders.

   The daemon still has to parse an SA payload and match it against its
   configured proposals to decide to refuse, so the round trip is a real
   daemon round trip. Building the request costs about a microsecond, three
   quarters of which is the `os.urandom(8)` read for the initiator SPI —
   everything after that SPI is a module constant. Over a whole run that is
   well under a millisecond of CPU, which is the only reason the figure is
   worth stating at all: the WireGuard approach this replaced would have cost
   2.9 seconds of pure-Python scalar multiplication per fleet scan.

   A reply counts only if it comes from the target address, echoes our
   initiator SPI, has exchange type 34 and the Response flag set. Accept and
   refuse are equally valid — both took one round trip.

   **NordVPN only.** PIA publishes an `ikev2` service and answers on it, but
   its IKE listener is unreliable exactly where its OpenVPN one is not: on
   seven far-east and virtual regions the OpenVPN UDP probe answered 3/3 while
   IKE answered 0/3 to 3/3 with 1.5-2.3 second outliers. AirVPN and Mullvad
   run no IKEv2 at all.

   **What it buys, stated honestly.** Against ICMP it looks decisive — 125/125
   NordVPN countries answer IKE where only 50/125 answer ping, and the 75
   ICMP-dark relays are 75 distinct IPs in 75 distinct countries. But
   `--probe openvpn` already reaches those same relays, 20/20, and agrees with
   IKE on RTT to within +2.4ms at the median. So this is a better-shaped
   instrument for relays the tool can already measure — one UDP datagram
   instead of a TCP session, on the right transport, measuring the protocol
   the user actually selected — not a fix for a blind spot.

5. **SOCKS5** — a minimal no-auth greeting (`05 01 00`) with the two-byte
   `05 00` reply timed. **No supported provider currently exposes a per-relay
   SOCKS5 endpoint reachable from outside its own tunnel**, so this finds
   nothing today; see [provider-notes.md](provider-notes.md).

The probe kind reaching the output (`icmp`, `tcp/443`, `socks5/1080`, …) tells
you which rung answered. A relay that only answers on TCP is not directly
comparable with one that answers on ICMP — the TCP number includes a
three-way handshake — so treat a mixed table with that in mind.

**Relays with several entry addresses.** AirVPN publishes up to four IPv4 entry
IPs per logical server, and PIA exposes several per-protocol endpoints per
region. All of a relay's targets are probed concurrently and the best one
represents the relay, where "best" is `probe_cost_ms` — the same cost function
that ranks relays, not raw RTT. Choosing on raw RTT picked a target answering
in 10ms while dropping half its packets over a clean one at 20ms.

**Concurrency.** `probe_all` bounds relay-level concurrency *and* the number of
individual probe targets in flight, both at the same limit. That second bound
matters: relay concurrency alone understates the real load, because one relay
can fan out to four IPs, and pinging four entry IPs of eighty relays at once
induces exactly the packet loss the score then charges for. The default flow
uses 80; `scan` defaults to 100 and takes `--concurrency`.

**Hostname resolution.** Relay hostnames are resolved over DNS-over-HTTPS
(Cloudflare's JSON API), never through the system resolver, so a hijacked,
captive-portal or geo-skewed local DNS cannot bias which IP gets measured.
Results are memoised in-process and concurrent lookups of the same hostname
collapse into one query.

## The warm-up packet, and why it keys on `icmp_seq`

The first packet to a relay pays for ARP and route resolution, so it is
discarded. The subtlety is *which* sample is the first packet's.

Discarding `samples[0]` is wrong, because `samples` holds only the replies that
came back. If the cold packet was the one that got lost — precisely the case
the discard exists for — then `samples[0]` is a warm sample and throwing it
away destroys good data. And if a *later* packet was lost, the cold sample is
still sitting at index 0 and gets kept. For
`icmp_seq=0 time=100ms / icmp_seq=1 time=10ms / timeout for seq 2`, the naive
rule keeps both replies and reports a median of 55ms instead of the warm 10ms.

Both BSD and GNU `ping` label every reply with its sequence number, so the cold
packet is *identified* rather than assumed: the reply whose `icmp_seq` equals
the platform's first sequence number is dropped (0 on macOS, 1 on Linux). If
that leaves nothing, all replies are kept rather than reporting nothing. On
platforms whose `ping` prints no sequence numbers, the tool falls back to
dropping `samples[0]`, and only when the run was complete — that is the only
case in which the first reply is provably the first packet.

TCP and SOCKS5 can attribute results to attempts directly, so they record a
per-attempt list including failures and drop index 0 only when the opening
attempt actually succeeded and at least two attempts did.

Per-probe numbers, after the discard:

- `rtt_ms` — median of the warm samples. Median, not mean: one slow packet
  should not move a five-packet result.
- `jitter_ms` — population standard deviation of the warm samples.
- `loss` — replies over packets sent, computed against *all* packets including
  the cold one, not against the warm subset.
- `attempts` — how many packets were actually sent. Recorded, not
  reconstructed, because loss only means something relative to it and it cannot
  be recovered once rounds of different sizes are merged.

## Multiple rounds

`--rounds N` (or `defaults.rounds`) probes every relay N times with a 0.5s gap,
then merges. Merging is keyed on `(provider, relay_id)`, because relay ids are
unique only within a provider — Mullvad uses hostnames, AirVPN public names,
PIA region slugs, NordVPN numeric ids — and keying on the id alone silently
merged two providers' samples.

For a merged relay:

- `rtt_ms` is the median of the per-round medians.
- `jitter_ms` is the population standard deviation of those per-round medians.
  That is a deliberately different quantity from the single-round jitter: it
  measures instability *between* rounds, which is what catches a link whose
  egress POP shifts underneath you (Starlink, mobile) and which per-round
  jitter cannot see.
- `loss` is total replies over total packets sent, summed across rounds — not
  the average of the per-round rates, which would weight a 2-packet TCP
  fallback round the same as a 5-packet ICMP round.
- the relay is reachable if any round reached it.

A relay is additionally flagged `flappy` when some rounds succeeded and others
failed, or when the spread between its per-round medians exceeds 50ms. The flag
is shown, not scored.

## What gets probed in the first place

Ranking honestly only helps if candidate selection is honest too. The default
flow selects, per provider:

- up to 60 relays in your detected country, nearest first by great-circle
  distance;
- one relay from each of the 6 nearest other countries, where "nearest" is
  computed from country centroids built out of the relay coordinates
  themselves, and only from countries some provider actually serves
  (`--here` skips this, `--nearby` is this, `--global` adds a spread of 40 more
  across every country served);
- if your country has no relays, the 8 nearest anywhere; if no location could
  be determined at all, 16 relays spread across as many countries as possible,
  and the output says so.

The scopes are strict about what they promise. `--here` means only your own
country: if a provider has no relay there it contributes nothing and says so,
rather than quietly offering an exit somewhere else. `--global` means *also*
worldwide, so it keeps the full in-country selection and adds breadth on top —
for NordVPN, whose inventory is fetched country-filtered to stay small, that
means fetching both the local and the worldwide set and merging them. Measured
from Montreal with NordVPN: `here` 60 relays in 1 country, `nearby` 61 in 2,
`global` 100 in 41 with the same 60 still local.

`--here` needs to know where "here" is. If no country can be determined, the
run widens to `nearby` and warns, rather than returning nothing.

NordVPN's inventory is too large to hand over whole, so it is first reduced to
a fixed number of servers spread round-robin over `(country, city)` buckets:
500 for the default flow, 50 for `scan`. That spread is what keeps the sample
wide — the inventory arrives ordered by server id, which clusters by country,
so simply taking the first 500 would return roughly one country.

Two rules keep this from importing provider judgement. First, within a NordVPN
city bucket the ordering is deterministic and independent of reported load —
sorting by load would mean the least-loaded box in each city is the only one
that ever gets measured, so a busy relay with better peering could never become
a candidate. Second, relays positioned only to a country centroid carry a 750km
distance penalty, so a coarse guess cannot outrank a relay whose position is
actually known.

`scan --geofilter K` applies the same distance filter to a single-provider
scan.

## A worked example

Two candidates, five packets each.

Relay A, NordVPN, reported load 40%. Four replies out of five packets, warm
median 18.4ms, jitter 2.2ms.

```text
observed loss    = 1 - 4/5              = 20%
confident loss   = Wilson lower bound   = 3.62%
loss penalty     = 300(0.0362) + 3000(0.0362)^2
                 = 10.87 + 3.93         = 14.80ms
jitter penalty   = 0.5 x 2.2            =  1.10ms
measured cost    = 18.4 + 14.80 + 1.10  = 34.30ms
load penalty     = 0.03 x 40            =  1.20ms
effective cost   = 34.30 + 1.20         = 35.50ms
```

Relay B, Mullvad (which publishes no load figure). Five replies out of five,
warm median 22.6ms, jitter 1.1ms.

```text
loss penalty     = 0                    =  0.00ms
jitter penalty   = 0.5 x 1.1            =  0.55ms
measured cost    = 22.6 + 0 + 0.55      = 23.15ms
effective cost   = 23.15                = 23.15ms
```

B wins by 12.35ms even though A's median RTT is 4.2ms lower. That is the
intended trade: one drop in five is not much evidence, but it is enough
evidence to matter at this margin, and it costs A more than its latency
advantage is worth.

Now add `penalties_ms = { nordvpn = 0.0, airvpn = 10.0, mullvad = 10.0, pia =
10.0 }` — a ten-millisecond preference for NordVPN. B becomes 33.15ms and A
stays at 35.50ms, so B still wins: an 11ms measured gap survives a 10ms
preference. That is what an absolute penalty buys you. Under the old
multiplicative weights the same "slight preference" would have scaled with
latency and quietly become an override on a slow link.

## Known limitations

- **Entry-IP RTT is not tunnel RTT.** Every probe here measures the path from
  this machine to the relay's *public entry address*. It says nothing about the
  relay's egress path, its available bandwidth, its CPU, or how WireGuard or
  OpenVPN will behave once traffic is encapsulated and the relay has to forward
  it. A relay 3ms closer on ICMP can easily be worse in the tunnel. Read the
  ranking as "which entry point is closest on this network right now".
- **At small packet counts, close relays are ordered by noise.** Five packets
  cannot separate relays a millisecond apart; the loss discount stops a single
  drop from dominating, but it cannot manufacture resolution that was never
  sampled. If two relays are within a few milliseconds, treat them as tied and
  raise `--rounds` or `--count` if you actually need to know.
- **Different rungs of the ladder are not directly comparable.** A `tcp/443`
  number includes a TCP handshake; an `icmp` number does not.
- **ICMP is deprioritised or rate-limited by some routers**, and some relays
  null-route it entirely. That is why the TCP fallback exists, but a relay that
  answers only on TCP may be measured slightly pessimistically.
- **The tool probes; it does not connect.** No throughput, no MTU discovery, no
  protocol-level handshake against the actual WireGuard or OpenVPN port.
- **Measuring from inside a tunnel measures the tunnel.** The default route is
  checked and a warning is printed, but the check is heuristic (interface name
  and gateway range) and can miss unusual setups.
- **Provider-reported load, provider preference and history are not
  measurements.** They are visible, separable, and off or minimal by default,
  but if you switch them on, the ordering you get is partly your own policy
  reflected back at you. `scan` without `--preferences` is the way to see the
  measurement alone.
