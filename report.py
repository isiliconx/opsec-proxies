"""Ad-hoc pool report: what actually earned a passing grade, and why."""
import sqlite3
import sys

DB = "data/resi.db"
c = sqlite3.connect(DB)
c.row_factory = sqlite3.Row

print("proxies cols:", ", ".join(r[1] for r in c.execute("pragma table_info(proxies)")))
print("tests cols  :", ", ".join(r[1] for r in c.execute("pragma table_info(tests)")))
print()

q = """
select t.asn as asn, t.isp as isp, count(*) n
from proxies p join tests t on t.proxy_id = p.id
where t.grade in ('A','B','C') and t.verdict in ('alive','slow')
group by t.asn order by n desc
"""
rows = list(c.execute(q))
print(f"=== {sum(r['n'] for r in rows)} passing rows, by ASN ===")
for r in rows[:15]:
    print(f"  {r['n']:>3}  {r['asn'] or '-':<18} {r['isp'] or ''}")

print()
print("=== residential signal ===")
try:
    n = c.execute("""select count(*) n from proxies p join tests t on t.proxy_id=p.id
                     where t.grade in ('A','B','C') and t.verdict in ('alive','slow')
                     and t.hosting = 0""").fetchone()["n"]
    print("  NOT flagged as hosting:", n)
except sqlite3.OperationalError as e:
    print("  (no such column)", e)

print()
print("=== what the C grade is made of ===")
try:
    for r in c.execute("""select t.grade, t.tls_ok, t.hosting, count(*) n
                          from tests t where t.verdict in ('alive','slow')
                          group by t.grade, t.tls_ok, t.hosting order by n desc"""):
        print(f"  grade={r['grade']} tls={r['tls_ok']} hosting={r['hosting']} n={r['n']}")
except sqlite3.OperationalError as e:
    print("  ", e)

print()
print("=== sample of passing rows ===")
q2 = """select p.scheme, p.host, p.port, t.grade, t.exit_ip, t.cc, t.isp, t.latency_ms, t.hosting, t.tls_ok
       from proxies p join tests t on t.proxy_id=p.id
       where t.grade in ('A','B','C') and t.verdict in ('alive','slow')
       order by t.latency_ms asc limit 12"""
for r in c.execute(q2):
    lat = f"{r['latency_ms']:.0f}ms" if r["latency_ms"] is not None else "-"
    print(f"  {r['grade']} {r['scheme']}://{r['host']}:{r['port']:<6} exit={r['exit_ip'] or '-':<16}"
          f" {r['cc'] or '-'} host={r['hosting']} tls={r['tls_ok']} {lat} {r['isp'] or ''}")
