# findings

Live results from the runs on this box. Every number below came out of
`run.py harvest` / `run.py test` / the PoCs — not estimated. The environment's
own exit IP rotates between the AWS ranges shown, so each run is stamped with
the `our exit` it observed.

## The honest headline

The harvest is large. The verified *residential* yield from purely open sources
is small, and the tool reports it as small. That is the correct result: a random
open proxy on a public port list is overwhelmingly a VPS on a hosting ASN, and
`recon/fingerprint.py` + the grade-A rule exist precisely to not pretend
otherwise. Real residential exits come in through **parcels** (`run.py import`),
which is why that path is a first-class part of the tool.

## Stage 1 — harvest

Feeds pulled on 2026-09-26, 27 enabled sources in `config/target.json`:

| metric | value |
|---|---|
| feeds returning data | 27 |
| raw bytes fetched | 2,714,398 |
| endpoints parsed | 36,748 |
| unique rows in `proxies` | 22,272 |

Feed-by-feed (endpoints parsed): hookzof-socks5 4000, proxifly-all 4000,
proxifly-http 4000, proxifly-socks5 4000, thespeedx-socks5 3694, thespeedx-http
3160, proxifly-socks4 634, proxyscrape-socks5 2630, thespeedx-socks4 2756,
mmpx12-socks4 661, jetkai-https 2161, vakhov-http 528, proxyscrape-http 1164,
hookzof/mmpx12/jackmw socks mix, proxynova-us 10, proxynova-de 7, zloi 172,
openproxylist 122, monosans-http 157, shiftytr 40, vakhov-https 6.

Five feeds in the original list were dead (404/502: proxyscrape v4, geonode,
proxy-list.download, clawnviper, jackmw) and were replaced with endpoints that
respond; the replaced list is in `config/target.json` and the last status of
every feed is in the `sources` table.

Note on parsing: several feeds ship with **no newlines at all** (proxifly,
hookzof, mmpx12). `recon/harvest.py` has a `url`/`crlf` parser that recovers
them with an anchored `host:port` token regex — without it those three feeds
parse to 0 or 1.

## Stage 3 — test + grade (live)

`run.py test --limit 900` against a 3,990-row queue:

| metric | value |
|---|---|
| candidates queued | 3,990 |
| TCP-reachable (pass 0) | 380 (~9.5%) |
| graded **alive** | 7 |
| grade C | 7 |
| grade A / B | 0 |
| wall time | 114 s for 900 rows (~8/s sustained, 900-wide) |

A separate run over 2,500 rows: 760 TCP-reachable, 0 alive at that moment — the
open pool's half-life is short and a batch tested minutes apart genuinely
disagrees. This is why `egress/service.py` re-reads the pool every 60 s and
`run.py test --since 6` exists.

Why A/B are 0 on open sources: grade A/B require a residential ASN or ISP PTR,
a non-cloud prefix, an exit IP different from ours, and TLS. The survivors above
carry hosting ASNs (see below), so they cap at C. That is the grade rule working,
not a gap in it.

## What the live exits actually are

From `exploit/poc_working_exit.py --grade C --limit 3` and
`exploit/poc_geo_rotate.py --n 5 --grade C`:

| exit ip | cc | asn | isp | residential? |
|---|---|---|---|---|
| 107.150.41.226 | US | AS33387 | Nocix, LLC | no (hosting) |
| 213.111.146.36 | NL | AS43641 | SOLLUTIUM EU Sp z.o.o. | no (hosting) |
| 185.195.71.218 | CH | AS56803 | Datasource AG | no (hosting) |

Every one of them: `same_as_us=False`, `anonymity=0.8`, `injected={}` — i.e. a
genuinely different exit, no `Via`/`X-Forwarded-For` injection, UA preserved.
`poc_geo_rotate` reported `distinct exits: 3, countries {US, NL, CH}, fails: 5` —
the 5 failures are the rotator working through dead entries.

The `residential=False` verdict is the classifier, not a failure. Nocix,
SOLLUTIUM and Datasource are hosting providers, so the exit ASN is a datacentre
and cannot be an A/B. Feed real ISP proxies in via `run.py import` and they
grade A/B.

## Detector evidence

From the `tests.evidence` column (json), the fields each detector contributes:

- **judge** (`t_transparent`) — `{"verdict":"transparent","exit_ip":"…","same_as_me":false,"anonymity_score":0.8,"injected":{}}`
- **handshake** (`tester`) — `{"ok":true,"scheme":"socks5","banner":"…"}` for a
  real SOCKS5 greeting; `{"ok":false,"errors":["socks5:…","http:…"]}` for a
  TCP port that is not a proxy
- **tls** (`t_tls`) — CONNECT + TLS upgrade to cloudflare/google/github with the
  response head recorded; `tls_ok:true` on every alive candidate
- **relay** (`t_leak`) — a neutral-target relay proof; the free open proxies that
  pass the handshake frequently accept the SOCKS greeting then drop the tunnel
  before the HTTP request, which the tester catches and grades D
- **portsweep** (`t_leak`) — same banner across ≥3 proxy ports ⇒ TSA/honeypot;
  these are excluded and `exploit/poc_tsa_exclusion.py --from-db 20` re-checks them
- **capture** (`t_capthive`) — marker posted to an echo endpoint; a proxy that
  rewrites the page or injects a script is graded D

Anonymity score composition (from `t_transparent.anonymity_score`): +0.5 exit IP
differs from ours, +0.3 no `Via`/`X-Forwarded-For` injection, +0.2 UA survived
→ the observed 0.8 means the exit differed and no headers were injected, but the
UA marker was not reflected by that particular judge.

## Detected and excluded classes

| class | how | evidence | grade |
|---|---|---|---|
| transparent (exit == ours) | `require_ip_change` + `same_as_me` | judge json | D |
| TSA / Airplane-mode honeypot | same banner on 80/443/8080/3128/8000/9110/8443 | `portsweep.identical` | D |
| open-relay banner | `squid`/`tinyproxy`/`gost` banner on the CONNECT reply | `handshake.banner` | downgraded |
| handshake-only fake (SOCKS greet, then drop) | judge returns no exit ip | `error: no exit ip from judge` | D |
| TLS MITM / captcha injection | marker not reflected, or `<script>` from a proxy vendor | `capture` | D |
| blacklisted exit | Spamhaus/Sorbs/Barracuda reverse zones | `blacklist` column | D |

## Reproduce

```bash
cd web/resiproxy
bash build.sh                       # install + compile + setup + full pipeline
python3 selftest.py                 # loopback proof of the whole chain
python3 run.py harvest
python3 run.py test --limit 2000
python3 run.py stats
python3 exploit/poc_geo_rotate.py --n 10 --grade C
python3 exploit/poc_tsa_exclusion.py --from-db 20
python3 exploit/poc_relay_proof.py --grade C --limit 2
```

`selftest.py` is the deterministic proof: it stands up a real loopback SOCKS5
relay and a real loopback HTTP forwarder, imports them as a parcel, runs them
through the real Tester (→ `alive/C`, `anonymity=0.8`, `tls=True`), reads them
back through `live_pool`, starts the real `ResiService`, and curls through both
the rotating SOCKS5 and the rotating HTTP listener (→ 200 with the upstream's exit
IP) plus the JSON API (→ 200). It ends `selftest: PASS`. It does not depend on
the open internet being in a good mood.
