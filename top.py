"""List the best-graded upstreams, by latest test per proxy."""
import sqlite3
import sys

GRADES = sys.argv[1] if len(sys.argv) > 1 else "A,B"
c = sqlite3.connect("data/resi.db")
c.row_factory = sqlite3.Row

rows = c.execute(
    """
    select p.host, p.port, p.scheme, p.origin, p.parcel_id,
           t.grade, t.verdict, t.exit_ip, t.cc, t.isp, t.asn,
           t.tls_ok, t.latency_ms, t.hosting, t.success_ratio, t.at
    from proxies p join tests t on t.proxy_id = p.id
    where t.id = (select id from tests where proxy_id = p.id order by at desc limit 1)
      and t.grade in ('A','B')
    order by t.latency_ms
    """
).fetchall()

print(f"grade A/B upstreams: {len(rows)}\n")
for r in rows:
    lat = f"{r['latency_ms']:.0f}ms" if r["latency_ms"] is not None else "-"
    ratio = f"{r['success_ratio']:.2f}" if r["success_ratio"] is not None else "-"
    print(f"  {r['grade']}  {r['scheme']}://{r['host']}:{r['port']:<6} "
          f"exit={(r['exit_ip'] or '-'):<16} {r['cc'] or '-'} host={r['hosting']} "
          f"tls={r['tls_ok']} ratio={ratio} {lat:>7}  {r['isp'] or ''}")

print()
n = c.execute(
    """select count(*) from proxies p join tests t on t.proxy_id=p.id
       where t.id=(select id from tests where proxy_id=p.id order by at desc limit 1)
       and t.grade in ('A','B')""").fetchone()[0]
print("total A/B:", n)
