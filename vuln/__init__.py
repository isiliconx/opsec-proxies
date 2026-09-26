"""Stage 3 — vuln. Detectors that decide what a candidate actually is.

These are the *classification* detectors. They answer four questions with real
rules and real evidence, and they are the reason the pool is 'highest quality':

  t_tls.py        does the proxy really terminate TLS (CONNECT to an https origin)
  t_transparent.py is the exit IP different from ours (真 anonymity) and is the
                   proxy injecting headers / rewriting the request
  t_leak.py       is it an OPEN RELAY that forwards to anything (should we use it?)
  t_capthive.py   is it a honeypot / TSA (Airplane-mode) that will fingerprint us
"""
