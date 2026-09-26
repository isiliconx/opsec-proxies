# opsec-proxies

Harvest open-proxy and open-residential feeds, verify and grade what actually
works, feed your own scraped parcels through the same tester, then route either
one Chrome window or the entire machine through the surviving pool.

Linux, macOS, Windows. Python 3.10+. One dependency: `aiohttp`.

```
harvest  ──▶  enum  ──▶  test/grade  ──▶  pool  ──▶  serve
                                                          ├─▶ chrome   (route A)
                                                          ├─▶ tunnel   (route B, system-wide)
                                                          └─▶ ui       (control panel)
```

## Build

```bash
bash build.sh              # install, compile-check, setup, then the full pipeline
bash build.sh --limit 5000 # same, capped
```

Windows: `build.bat`.

Prove the whole chain without depending on the open internet:

```bash
python3 selftest.py        # loopback relays -> parcel -> tester -> pool -> listeners
```

It ends `selftest: PASS`.

## Run

```bash
python3 run.py setup                    # create db/dirs, print your exit ip
python3 run.py harvest                  # stage 1, 27 feeds
python3 run.py harvest --only proxifly
python3 run.py test --limit 5000        # stage 3, verify + grade
python3 run.py test --origin import     # only your own parcels
python3 run.py pipeline                 # harvest + enum + test + export
python3 run.py stats
python3 run.py export artifacts/best.txt --grade A
python3 run.py pick --n 5 --grade A     # print the next 5 upstream URLs
python3 run.py ui                       # control panel, 127.0.0.1:8770
```

## Import your own parcels

```bash
python3 run.py import mylist.txt
python3 run.py import mylist.txt --scheme socks5 --test
python3 run.py import ./parcels/
cat mylist.txt | python3 run.py import -
python3 run.py test-parcel 3
```

Auto-detected, mixed files are fine: `host:port`, `scheme://host:port`,
`user:pass@host:port`, `http://user:pass@host:port`, comma/space/tab separated, a
JSON array, a pasted `curl -x …` command, a whole HTML page or log file, csv.
Credentials go to the sqlite db and never to a log — the log filter scrubs
`user:pass@host:port` and anything after `password=`/`token=`.

## Route A — Chrome only

```bash
python3 run.py serve --grade B        # SOCKS5 :2080, HTTP :2081, API :8770
python3 run.py chrome                 # --proxy-server=http://127.0.0.1:2081
```

Nothing else on the machine changes. No extension, no profile PAC, no system
settings. Close the listener and the browser is direct again.

## Route B — the whole machine

```bash
sudo python3 run.py tunnel --dry-run   # prints every command, writes nothing
sudo python3 run.py tunnel             # takes the default route
```

Prefers **sing-box**: real TUN device `resi0`, default route into it, outbound
dials the local SOCKS listener so the pool keeps rotating underneath. Falls back
to `tun2socks`.

Killswitch goes up before the route and comes down after:

| os | mechanism |
|----|-----------|
| Linux | `nft` table `inet resiproxy` — output/forward policy drop, accept only the TUN, loopback, CGNAT, established |
| macOS | `pf` anchor `resiproxy` — block out, pass on `resi0`, pass route-to `lo0` |
| Windows | `netsh advfirewall` outbound block rule |

Routing excludes RFC1918, `169.254.0.0/16` and CGNAT, so local traffic and LAN
stay local.

## Grades

| grade | means |
|-------|-------|
| **A** | residential ASN or ISP PTR, not a cloud prefix, exit IP differs from ours, TLS ok, fast, reliable |
| **B** | verified exit, one soft signal missing |
| **C** | alive but datacentre ASN, or flaky, or relay-ish |
| **D** | dead, transparent (exit == ours), TSA/honeypot, MITM, blacklisted |

Only pass-3 survivors cost a geo lookup, so the rate-limited ip-api budget goes
to rows that are actually alive.

## PoCs

One command each, real evidence, exit code is the verdict.

```bash
python3 exploit/poc_working_exit.py --grade A --limit 3
python3 exploit/poc_geo_rotate.py --n 10 --grade A
python3 exploit/poc_relay_proof.py --grade B --limit 2
python3 exploit/poc_tsa_exclusion.py --from-db 20
```

## What the numbers actually say

`findings.md` has the live run: 36,748 endpoints harvested from 27 feeds,
22,272 unique rows, 900 tested → 380 TCP-reachable → 7 alive. The seven sit on
hosting ASNs, so they cap at grade C. Grade A/B comes from imported ISP proxies,
not from random open lists — the classifier is built to refuse to call a VPS a
home connection.

## Layout

```
recon/       harvest.py, fingerprint.py                       stage 1
enum/        queue.py, ports.py                               stage 2
vuln/        tester.py + t_tls / t_transparent / t_leak / t_capthive   stage 3
exploit/     poc_working_exit, poc_geo_rotate, poc_relay_proof, poc_tsa_exclusion
tooling/     httpclient, dns, socks_server, geo, session, mutator, parcel,
             config, db, limiter, pac, modload, logging_util
egress/      service, chrome, tunnel
ui/          server.py, index.html
config/      target.json
```

`tooling/httpclient.py` is a hand-rolled HTTP/1.1 client over asyncio streams
rather than aiohttp: the tester needs the raw CONNECT banner bytes for
classification, and pinning aiohttp's private connector internals breaks on its
3.14 release. DNS is a resolver written in-tree — no dnspython.

## Config

`config/target.json` holds every knob: feed list, tester concurrency and
timeouts, the reject lists, blacklist zones, every classification keyword set,
geo providers, listener ports, failover and sticky-session behaviour, the tunnel
engine and interface, killswitch per OS, and the local-handling settings.

Listeners bind `127.0.0.1` only. Nothing is uploaded anywhere; artifacts stay
under the project directory.

## What breaks

- **Feeds rot.** Public lists have a short half-life. `run.py harvest` takes 12 s
  for ~37k rows — run it on a schedule. `sources.last_status` shows which feed died.
- **Dead proxies rot faster.** An hour-old grade is a guess. `serve` re-reads the
  pool every 60 s; `test --since 6` re-verifies the recent window.
- **The tunnel needs a TUN binary.** `run.py tunnel --dry-run` tells you exactly
  what is missing. Windows needs Wintun and an elevated shell.
- **Killswitch state.** If a `tunnel` run is killed hard, drop the nft table by
  hand: `sudo nft delete table inet resiproxy`.
- **ip-api is 15 req/min** on the free tier. The tester only spends it on pass-3
  survivors; a bigger pool just gets slower, and `tooling/geo.py` falls back to
  ipwho.is.
