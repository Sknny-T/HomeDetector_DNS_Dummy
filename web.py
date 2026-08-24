#!/usr/bin/env python3
"""
dns_anomaly_web.py

A tiny Flask front-end for triggering Home Detector's DNS Anomaly Detector,
same idea as dns_anomaly_trigger.py, but with a physical/on-screen button on
a webpage instead of pressing Enter in a terminal.

WHAT IT DOES
------------
Runs a background thread that repeatedly resolves a handful of "baseline"
domains, like a normal IoT device would. It also serves a small webpage with
a big button, press it (or POST to /trigger) and it does one lookup of a
different "anomaly" domain instead. If Home Detector is watching this host,
that should show up as a new alert in its Admin UI.

HOW HOME DETECTOR ACTUALLY DECIDES "NEW" (read this before you get confused)
------------------------------------------------------------------------
Home Detector doesn't alert on the exact hostname you query. For every
query it does its own upstream SOA lookup to find the *authoritative*
domain (e.g. "www.foo.example.com" -> "example.com"), and it's that
authoritative domain which gets tracked per network scope in its database
(dns/listener.py -> findDomain()/sqlDomains()). Two consequences:

 1. Querying a new subdomain of an already-seen domain will NOT trigger an
    alert by default (only the registrable domain matters), unless you've
    turned on the add-on's "detect_on_host_query" option, which additionally
    tracks exact hostnames.
 2. ANOMALY_DOMAIN needs to be a domain that *actually resolves* (has a
    real SOA record). If the SOA lookup fails, Home Detector falls back to
    "soa_failure_action" (default: ignore), which does NOT raise an alert.
    Don't point this at a made-up hostname unless you've set
    soa_failure_action: block in the add-on config.

You also need to make sure:

 * The machine running this script is inside a network/host scope you've
   configured in the add-on (Configuration -> Local IoT Networks). An
   unrecognised source IP is treated per "Unknown IP (Default) Action"
   (default: ignore) and won't alert either.
 * That scope has left "learning mode" so new domains actually raise an
   alert instead of silently being learned. For a fast demo, set
   "Learning Mode Duration" (learning_duration) to 0 in the add-on config
   and restart it, that flips new scopes to "block" (= alerting) mode
   almost immediately instead of the 30-day default.
 * This script's DNS queries actually go THROUGH Home Detector, not your
   normal upstream resolver. Either point this machine's DNS at the Home
   Assistant host (Home Detector listens on port 53, mapped from its
   internal 10053), or just set --resolver/--port below to talk to it
   directly without touching your system's DNS settings at all.

USAGE
-----
    pip install flask dnspython
    python3 dns_anomaly_web.py --resolver 192.168.1.10 --port 53
    python3 dns_anomaly_web.py --baseline example.com,wikipedia.org --anomaly github.com
    python3 dns_anomaly_web.py --web-host 0.0.0.0 --web-port 5000   # reachable from your phone/tablet

Then open http://<this-machine>:5000/ and press the button.

Endpoints:
    GET  /         the button + recent activity log
    GET  /status   JSON: config + recent log (used by the page's auto-refresh)
    POST /trigger  fires one anomaly-domain lookup, returns JSON result
"""

import argparse
import random
import threading
from collections import deque
from datetime import datetime, timezone

try:
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdatatype
except ModuleNotFoundError:
    raise SystemExit("This script needs dnspython. Install it with: pip install dnspython")

try:
    from flask import Flask, jsonify, render_template_string, request
except ModuleNotFoundError:
    raise SystemExit("This script needs Flask. Install it with: pip install flask")

QUERY_TIMEOUT = 5  # Seconds to wait for a DNS response
LOG_MAXLEN = 100

app = Flask(__name__)

# Populated from CLI args in main(), read by request handlers and the
# background thread. Simple module-level config is fine, this app only
# ever serves one operator on their own LAN.
CONFIG = {
    "resolver_ip": "192.168.2.1",
    "resolver_port": 53,
    "baseline_domains": ["example.com", "wikipedia.org"],
    "anomaly_domain": "duckduckgo.com",
    "interval": 15,
}

log = deque(maxlen=LOG_MAXLEN)  # Most recent lookups, newest first
log_lock = threading.Lock()
stop_event = threading.Event()


def now():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def resolve(qname: str, timeout: float = QUERY_TIMEOUT):
    """
    Send a single A-record query straight at Home Detector's DNS listener
    (bypassing whatever resolver this machine is normally configured to
    use) and return (success: bool, summary: str).
    """
    query = dns.message.make_query(qname, dns.rdatatype.A)
    try:
        response = dns.query.udp(query, CONFIG["resolver_ip"], port=CONFIG["resolver_port"], timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - test tool, just report it
        return False, f"FAILED ({type(exc).__name__}: {exc})"

    answers = [str(rr) for rrset in response.answer for rr in rrset]
    if not answers:
        return False, f"No answer (rcode={dns.rcode.to_text(response.rcode())})"
    return True, "; ".join(answers)


def record(kind, domain, ok, detail):
    entry = {"time": now(), "kind": kind, "domain": domain, "ok": ok, "detail": detail}
    with log_lock:
        log.appendleft(entry)
    print(f"[{entry['time']}] [{kind}] {'OK' if ok else '!!'} {domain} -> {detail}", flush=True)
    return entry


def baseline_loop():
    """Background thread: behave like a normal, boring IoT device."""
    while not stop_event.is_set():
        domain = random.choice(CONFIG["baseline_domains"])
        ok, detail = resolve(domain)
        record("baseline", domain, ok, detail)
        stop_event.wait(CONFIG["interval"])


PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Home Detector - DNS Anomaly Trigger</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.3rem; }
  .config { font-size: 0.85rem; opacity: 0.75; margin-bottom: 1.5rem; line-height: 1.5; }
  .config code { font-weight: 600; }
  button#fire {
    display: block; width: 100%; padding: 1.25rem; font-size: 1.2rem; font-weight: 700;
    color: #fff; background: #d33; border: none; border-radius: 10px; cursor: pointer;
  }
  button#fire:active { background: #a00; }
  button#fire:disabled { background: #999; cursor: wait; }
  #result { margin-top: 0.75rem; font-size: 0.9rem; min-height: 1.4em; }
  table { width: 100%; border-collapse: collapse; margin-top: 1.5rem; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid rgba(128,128,128,0.25); }
  .ok { color: #2a8f4d; }
  .fail { color: #d33; }
  .kind-anomaly { font-weight: 700; }
</style>
</head>
<body>
  <h1>🐕 Home Detector - DNS Anomaly Trigger</h1>
  <div class="config">
    Resolver: <code>{{ resolver_ip }}:{{ resolver_port }}</code><br>
    Baseline domains (queried every {{ interval }}s): <code>{{ baseline_domains|join(', ') }}</code><br>
    Anomaly domain: <code>{{ anomaly_domain }}</code>
  </div>

  <button id="fire">Trigger DNS Anomaly ({{ anomaly_domain }})</button>
  <div id="result"></div>

  <table>
    <thead><tr><th>Time</th><th>Type</th><th>Domain</th><th>Result</th></tr></thead>
    <tbody id="log"></tbody>
  </table>

<script>
async function refresh() {
  const r = await fetch('/status');
  const data = await r.json();
  const tbody = document.getElementById('log');
  tbody.innerHTML = '';
  for (const e of data.log) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${e.time}</td>` +
      `<td class="${e.kind === 'anomaly' ? 'kind-anomaly' : ''}">${e.kind}</td>` +
      `<td>${e.domain}</td>` +
      `<td class="${e.ok ? 'ok' : 'fail'}">${e.detail}</td>`;
    tbody.appendChild(tr);
  }
}

document.getElementById('fire').addEventListener('click', async () => {
  const btn = document.getElementById('fire');
  const result = document.getElementById('result');
  btn.disabled = true;
  result.textContent = 'Looking up...';
  try {
    const r = await fetch('/trigger', { method: 'POST' });
    const data = await r.json();
    result.textContent = data.ok
      ? `OK -> ${data.detail}. Check the Home Detector Admin UI for a new alert.`
      : `Lookup failed -> ${data.detail}`;
  } catch (err) {
    result.textContent = 'Request failed: ' + err;
  } finally {
    btn.disabled = false;
    refresh();
  }
});

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE, **CONFIG)


@app.route("/status")
def status():
    with log_lock:
        entries = list(log)
    return jsonify({"config": CONFIG, "log": entries})


@app.route("/trigger", methods=["POST"])
def trigger():
    domain = CONFIG["anomaly_domain"]
    ok, detail = resolve(domain)
    entry = record("anomaly", domain, ok, detail)
    return jsonify(entry)


def main():
    parser = argparse.ArgumentParser(description="Web UI for triggering Home Detector's DNS anomaly detector.")
    parser.add_argument("--resolver", default=CONFIG["resolver_ip"],
                        help="IP of Home Detector's DNS listener (usually your Home Assistant host)")
    parser.add_argument("--port", type=int, default=CONFIG["resolver_port"],
                        help="Port Home Detector's DNS listener is exposed on (default 53)")
    parser.add_argument("--baseline", default=",".join(CONFIG["baseline_domains"]),
                        help="Comma-separated list of 'normal' domains to keep querying")
    parser.add_argument("--anomaly", default=CONFIG["anomaly_domain"],
                        help="Domain to switch to when triggered, must actually resolve, see script docstring")
    parser.add_argument("--interval", type=float, default=CONFIG["interval"], help="Seconds between baseline lookups")
    parser.add_argument("--web-host", default="127.0.0.1",
                        help="Interface for the Flask web server to bind (0.0.0.0 to reach it from other devices)")
    parser.add_argument("--web-port", type=int, default=5000, help="Port for the Flask web server")
    parser.add_argument("--no-baseline", action="store_true",
                        help="Don't run the background baseline loop, button-only")
    args = parser.parse_args()

    CONFIG["resolver_ip"] = args.resolver
    CONFIG["resolver_port"] = args.port
    CONFIG["baseline_domains"] = [d.strip() for d in args.baseline.split(",") if d.strip()]
    CONFIG["anomaly_domain"] = args.anomaly
    CONFIG["interval"] = args.interval

    print("Home Detector DNS anomaly web trigger")
    print(f"  Resolver : {CONFIG['resolver_ip']}:{CONFIG['resolver_port']}")
    print(f"  Baseline : {CONFIG['baseline_domains']}")
    print(f"  Anomaly  : {CONFIG['anomaly_domain']}")
    print(f"  Web UI   : http://{args.web_host}:{args.web_port}/")
    print()

    if not args.no_baseline:
        thread = threading.Thread(target=baseline_loop, daemon=True)
        thread.start()

    try:
        app.run(host=args.web_host, port=args.web_port, debug=False)
    finally:
        stop_event.set()


if __name__ == "__main__":
    main()