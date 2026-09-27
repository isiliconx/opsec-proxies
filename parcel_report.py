"""Break down parcel 2 by verdict and the error text, so we can see whether
the losses are port-shape, protocol, or pure death."""
import sqlite3
from collections import Counter

c = sqlite3.connect("data/resi.db")
c.row_factory = sqlite3.Row

rows = c.execute("""
    select p.host, p.port, p.scheme, p.origin,
           t.grade, t.verdict, t.error, t.exit_ip, t.cc, t.isp, t.tls_ok, t.latency_ms
    from proxies p left join tests t
      on t.proxy_id = p.id
     and t.id = (select id from tests where proxy_id = p.id order by at desc limit 1)
    where p.parcel_id = 2
    order by p.port
""").fetchall()

print(f"parcel 2: {len(rows)} rows\n")
print("grades :", dict(Counter((r["grade"] or "untested") for r in rows)))
print("verdict:", dict(Counter((r["verdict"] or "-") for r in rows)))

print("\n=== why each one failed ===")
errs = Counter()
for r in rows:
    e = (r["error"] or "")[:70] or "untested"
    errs[e] += 1
for e, n in errs.most_common():
    print(f"  {n:>3}  {e}")

print("\n=== the ones that lived ===")
for r in rows:
    if r["grade"] in ("A", "B", "C"):
        print(f"  {r['grade']}  {r['scheme']}://{r['host']}:{r['port']:<6} "
              f"exit={r['exit_ip']} {r['cc']} tls={r['tls_ok']} {r['isp']}")

print("\n=== scheme split among the dead ===")
dead = [r for r in rows if (r["verdict"] or "") == "dead"]
print(" ", dict(Counter(r["scheme"] for r in dead)))
print("=== scheme split among the alive ===")
alive = [r for r in rows if r["verdict"] in ("alive", "slow")]
print(" ", dict(Counter(r["scheme"] for r in alive)))
