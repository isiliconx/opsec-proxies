# opsec-proxies — design and internals

Harvest open-proxy/open-residential feeds, verify and grade what actually works, take
imported parcels through the same tester, then route either one Chrome window or the
whole machine through the surviving pool.

Linux, macOS, Windows. Python 3.10+. One dependency: `aiohttp`.

```
harvest  ->  enum  ->  test/grade  ->  pool  ->  serve
                                                   |-> chrome   (route A)
                                                   |-> tunnel   (route B, system-wide)
                                                   |-> ui       (control panel)
```

---

## Build and run

```bash
bash build.sh              # install, compile-check, setup, then the full pipeline
bash build.sh --limit 5000 # same, but cap the test stage
```

Windows: `build.bat`.

Everything is also callable directly:

```bash
python3 run.py setup                       # create db/dirs, print your exit ip
python3 run.py harvest                     # stage 1, ~27 feeds
python3 run.py harvest --only proxifly
python3 run.py test --limit 5000           # stage 3, verify + grade
python3 run.py test --origin import        # only your own parcels
python3 run.py pipeline                    # harvest + enum + test + export, one shot
python3 run.py stats                       # grade and country counts
python3 run.py export artifacts/best.txt --grade A
python3 run.py pick --n 5 --grade A        # print the next 5 upstream URLs
```

---

## Stage 1 — harvest (`recon/`)

`recon/harvest.py` pulls every feed in `config/target.json → harvest.sources` and parses
five payload shapes:

| kind    | shape                                                     | feeds |
|---------|-----------------------------------------------------------|-------|
| `text`  | one `ip:port` per line                                     | proxyscrape |
| `crlf`  | one per line, CRLF, **or every line concatenated**         | thespeedx, monosans, hookzof, mmpx12, jetkai, vakhin, roosterkid, zloi |
| `url`   | `scheme://[user:pass@]ip:port` with no newlines            | proxifly |
| `html`  | scraped table                                             | proxynova (us, de) |
| `range` | `start-end` / `prefix` in ISP or CGNAT space               | iplocate ISP/mobile |

Raw bodies land in `data/harvest/<feed>.txt`. Rows land in `data/resi.db` table `proxies`,
deduped on `(scheme, host, port, user)`. `sources` table records the last run and yield per
feed, so a feed that goes quiet is visible in `run.py stats` instead of silently rotting.

`recon/fingerprint.py` is the classifier that makes the pool high quality. It answers
"is this a real access network or a VPS" from three independent signals:

- `in_cloud()` — is the exit inside a published cloud prefix (AWS/GCP/Azure/DO/Hetzner/…)
- `ptr_verdict()` — does the PTR read like an ISP access network (`cpe-`, `pool-`, `dsl-`,
  `pppoe-`, an operator name) or like a datacentre (`cloud`, `vps`, `dedi`, `amazonaws`)
- `asn_verdict()` — same question against the ASN/ISP/ORG string

`enum/queue.py` tiers the queue so the 900-wide tester never spends budget on a dead port
while a live one is waiting: random residential ports first (`3xxx`/`5xxx`/`9xxx`), then
the common proxy ports, then everything else, with SSH/RDP/DB/Redis ports hard-rejected.

`enum/ports.py` is the port-discovery pass: for each host it re-probes the standard proxy
ports for a SOCKS5/SOCKS4 greeting or a proxy banner and writes the new combinations back
as `origin=enum` rows.

## Stage 2 — parcels (`tooling/parcel.py`)

Your own scraped residential proxies, in, tested, in the same pool. Tagged
`origin=import`, linked to a `parcels` row so you can see per-parcel pass/fail.

```bash
python3 run.py import mylist.txt
python3 run.py import mylist.txt --scheme socks5 --test
python3 run.py import ./parcels/                 # whole directory
cat mylist.txt | python3 run.py import -          # stdin
python3 run.py test-parcel 3                      # re-test one parcel
```

Auto-detected, mixed files are fine: `host:port`, `scheme://host:port`,
`user:pass@host:port`, `http://user:pass@host:port`, comma/space/tab separated, a JSON
array, a pasted `curl -x …` command, a whole HTML page or log file (candidates are
extracted), csv. Credentials go to the db and are never written to a log — the log
filter scrubs `user:pass@host:port` and anything after `password=`/`token=`.

## Stage 3 — test and grade (`vuln/`)

Four passes, cheapest first, per candidate:

| pass | what | timeout | kills |
|------|------|---------|-------|
| 0 | TCP reachability | 3s | most of the pool |
| 1 | protocol handshake, capture banner (`vuln/tester.py`) | 3–5s | non-proxies |
| 2 | judge + anonymity (`vuln/t_transparent.py`) | 8s | non-forwarders |
| 3 | TLS + relay + capture + geo + blacklist | 8s | — |

Only pass-3 survivors cost a geo lookup, so the rate-limited ip-api budget goes to rows
that are actually alive.

**Grades**

| grade | means |
|-------|-------|
| **A** | residential ASN or ISP PTR, not a cloud prefix, exit IP differs from ours, TLS ok, < 2.5 s, reliability ≥ floor |
| **B** | verified exit and one soft signal missing, or slow, or no TLS |
| **C** | alive but datacentre ASN, or flaky, or relay-ish |
| **D** | rejected: dead, transparent (exit == ours), TSA/honeypot, MITM, blacklisted |

`tester.classification.*` in the config holds the keyword sets — DC ASN keywords, relay
banner keywords, resnet banner keywords, TSA banner markers. Edit them there, not in code.

**Detectors**

- `vuln/t_tls.py` — CONNECT + TLS upgrade with SNI to cloudflare/google/github, records
  the response head as evidence
- `vuln/t_transparent.py` — exit IP vs our IP (score 0.5 for a different exit, 0.3 for no
  `Via`/`X-Forwarded-For` injection, 0.2 for a surviving UA), five fall-back judges
- `vuln/t_leak.py` — open-relay proof against neutral targets, TSA banner detection,
  `PortSweep` for the honeypot signature (same banner on ≥ 4 proxy ports)
- `vuln/t_capthive.py` — posts a marker to an echo endpoint; a proxy that rewrites the page
  or injects a script is graded D

Geo comes from `tooling/geo.py`: ip-api in 100-IP batches at 15 req/min, `ipwho.is` as
fallback, 14-day sqlite cache, PTR through `tooling/dns.py` (a resolver written from
scratch — no dnspython), blacklist lookups in `reversed-ip.zone` form.

## Stage 4 — PoCs (`exploit/`)

One command each, real evidence, exit code is the verdict.

```bash
python3 exploit/poc_working_exit.py --grade A --limit 3
python3 exploit/poc_geo_rotate.py --n 10 --grade A
python3 exploit/poc_relay_proof.py --grade B --limit 2
python3 exploit/poc_tsa_exclusion.py --from-db 20
```

## Route A — Chrome only

```bash
python3 run.py serve --grade B        # SOCKS5 :2080, HTTP :2081, API :8770
python3 run.py chrome                 # launches Chrome with --proxy-server=http://127.0.0.1:2081
python3 run.py chrome --headless https://ipinfo.io
```

Nothing else on the machine is touched. No extension, no profile PAC, no system settings.
The browser points at the local listener; the listener binds each connection to a verified
residential upstream. Close the listener and the browser is direct again.

`egress/chrome.py` finds Chrome/Chromium/Edge on all three platforms and builds the argv;
every privacy-relevant default is on (`--no-first-run`, `--password-store=basic`,
`--dns-prefetch-disable`, background networking and component updates off).

## Route B — the whole machine

```bash
sudo python3 run.py tunnel --dry-run   # prints every command, writes nothing
sudo python3 run.py tunnel             # actually takes the default route
```

`egress/tunnel.py` prefers **sing-box**: it creates a real TUN device (`resi0`), puts the
default route into it, and its outbound dials our local SOCKS listener — so sing-box never
needs to know the pool, and the pool keeps rotating underneath it. Fallback is
`tun2socks` if that is what the box has.

The killswitch goes up *before* the route and comes down after it:

| os | mechanism |
|----|-----------|
| Linux | `nft` table `inet resiproxy` — output/forward policy drop, accept only the TUN, loopback, CGNAT and established |
| macOS | `pf` anchor `resiproxy` — block out, pass on `resi0`, pass route-to `lo0` |
| Windows | `netsh advfirewall` outbound block rule |

Routing excludes RFC1918, link-local (`169.254.0.0/16`, which is where the cloud metadata
service lives) and CGNAT, so local traffic and LAN stay local.

## The pool service (`egress/service.py`)

`python3 run.py serve` brings up:

| port | what |
|------|------|
| 2080 | SOCKS5 (RFC 1929 auth if you set `--auth user:pass`) |
| 2081 | HTTP — `CONNECT` and absolute-form GET/POST |
| 8770 | JSON API: `/api/status`, `/api/pool`, `/api/exit`, `/api/refresh` |
| 8771 | `/proxy.pac` — routes through 2080, keeps loopback/LAN/CGNAT/metadata direct |

`tooling/socks_server.py` does the rotation: weighted-random inside the healthiest 30% of
the pool, sticky sessions (`X-Resi-Session` header, or a PAC session id) so a tab keeps one
exit, exponential cooldown on failure, and mid-connection re-bind so a proxy that dies
never reaches the browser. The pool is re-read from sqlite every 60 s, so a fresh
`run.py test` shows up without a restart.

```bash
curl -x socks5h://127.0.0.1:2080 https://ipinfo.io     # one rotating exit
curl http://127.0.0.1:8770/api/exit?n=3&grade=A        # pick 3 and print them
```

## Control panel (`ui/`)

```bash
python3 run.py ui      # http://127.0.0.1:8770
```

Pool table with live grades/exits/ASNs, filterable; parcel import with a paste box that
accepts any of the formats above and tests on arrival; buttons for both routes. Bound to
127.0.0.1, CORS-open for local tools, and gated by `ui.auth_token` if you set one.

## Config (`config/target.json`)

| block | what it controls |
|-------|------------------|
| `harvest` | feed list, concurrency, timeouts, range-feed cap |
| `tester` | concurrency, per-pass timeouts, judge URL, sample count, reject lists, blacklist zones, every classification keyword set |
| `geo` | batch size, primary/fallback providers, cache TTL |
| `egress` | listen host, the four ports, failover, sticky seconds, cooldown, refresh interval, browser argv, tunnel engine/interface/MTU, killswitch per OS |
| `ui` | bind, port, autopen, token |
| `opsec` | raw-body persistence, log scrubbing, log age, UA pool |

The listeners bind `127.0.0.1` only. Nothing is uploaded anywhere; artifacts stay under
the project dir.

## Layout

```
recon/       harvest.py, fingerprint.py        stage 1
enum/        queue.py, ports.py                stage 2
vuln/        tester.py + t_tls / t_transparent / t_leak / t_capthive    stage 3
exploit/     poc_working_exit, poc_geo_rotate, poc_relay_proof, poc_tsa_exclusion
tooling/     httpclient, dns, socks_server, geo, session, mutator, parcel,
             config, db, limiter, pac, modload, logging_util
egress/      service, chrome, tunnel
ui/          server.py, index.html
config/      target.json
run.py       orchestrator · build.sh / build.bat · findings.md
```

`tooling/httpclient.py` is a hand-rolled HTTP/1.1 client over asyncio streams rather than
aiohttp: the tester needs the raw CONNECT banner bytes for classification, and pinning
aiohttp's private connector internals would have broken on its 3.14 release.

## What breaks

- **Feeds rot.** Public free-proxy lists have a short half-life. `run.py harvest` is cheap
  (12 s, ~37k rows); run it on a schedule. `sources.last_status` shows which feed died.
- **Dead proxies rot faster.** An hour-old grade is a guess. `serve` re-reads every 60 s and
  `test --since 6` re-verifies the recent window; schedule both on a timer.
- **The tunnel needs a TUN binary.** `sing-box` is the good one; `run.py tunnel --dry-run`
  tells you exactly what is missing. Windows needs Wintun, and needs an elevated shell.
- **Killswitch state.** If a `tunnel` run is killed hard, drop the `nft` table by hand:
  `sudo nft delete table inet resiproxy`.
- **ip-api is 15 req/min on the free tier.** The tester only spends it on pass-3 survivors;
  a bigger pool than that will just get slower, and `tooling/geo.py` falls back to ipwho.is.
