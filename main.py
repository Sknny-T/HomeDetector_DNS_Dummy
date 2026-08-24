#!/usr/bin/env python3
"""
dns_anomaly_trigger.py

A tiny test harness for Home Detector's DNS Anomaly Detector.

WHAT IT DOES
------------
Runs a background loop that repeatedly resolves a handful of "baseline"
domains, like a normal IoT device would. Whenever you press ENTER (or run
with --once), it does a single lookup of a "anomaly" domain instead, one
Home Detector hasn't seen from this host before. If everything is wired up
correctly, that lookup should show up as a new alert in the Home Detector
Admin UI (and flip the traffic-light entity red, if you've got that add-on
patch too).

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
   internal 10053), or just set RESOLVER_IP/RESOLVER_PORT below to talk to
   it directly without touching your system's DNS settings at all.

USAGE
-----
    pip install dnspython
    python3 dns_anomaly_trigger.py                  # interactive
    python3 dns_anomaly_trigger.py --once            # fire one anomaly lookup and exit
    python3 dns_anomaly_trigger.py --resolver 192.168.1.10 --port 53
    python3 dns_anomaly_trigger.py --baseline example.com,wikipedia.org --anomaly github.com

While it's running:
    ENTER   -> fire one anomaly-domain lookup right now
    q ENTER -> quit
"""

import argparse
import random
import sys
import threading
import time
from datetime import datetime, timezone

try:
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdatatype
except ModuleNotFoundError:
    print("This script needs dnspython. Install it with: pip install dnspython")
    sys.exit(1)

# ----------------------------------------------------------------------
# Defaults - override any of these with command-line flags, see --help
# ----------------------------------------------------------------------
DEFAULT_RESOLVER_IP = "192.168.2.1"  # Point this at your Home Assistant host's IP
DEFAULT_RESOLVER_PORT = 53  # Home Detector's DNS listener (10053 internally, mapped to 53)
DEFAULT_BASELINE_DOMAINS = ["example.com", "wikipedia.org"]  # "Normal" traffic for this fake device
DEFAULT_ANOMALY_DOMAIN = "duckduckgo.com"  # Must be a real, resolvable domain, see docstring
DEFAULT_INTERVAL = 15  # Seconds between baseline lookups
QUERY_TIMEOUT = 5  # Seconds to wait for a response


def resolve(qname: str, resolver_ip: str, resolver_port: int, timeout: float = QUERY_TIMEOUT):
    """
    Send a single A-record query straight at Home Detector's DNS listener
    (bypassing whatever resolver this machine is normally configured to
    use) and return (success: bool, summary: str).
    """
    query = dns.message.make_query(qname, dns.rdatatype.A)
    try:
        response = dns.query.udp(query, resolver_ip, port=resolver_port, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - this is a test tool, we just want to report it
        return False, f"FAILED ({type(exc).__name__}: {exc})"

    answers = [str(rr) for rrset in response.answer for rr in rrset]
    if not answers:
        return False, f"No answer (rcode={dns.rcode.to_text(response.rcode())})"
    return True, "; ".join(answers)


def now():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def baseline_loop(domains, resolver_ip, resolver_port, interval, stop_event):
    """
    Background thread: behave like a normal, boring IoT device, look up the
    same handful of known-good domains, forever, until asked to stop.
    """
    while not stop_event.is_set():
        domain = random.choice(domains)
        ok, detail = resolve(domain, resolver_ip, resolver_port)
        tag = "OK" if ok else "!!"
        print(f"[{now()}] [baseline] {tag} {domain} -> {detail}")
        stop_event.wait(interval)


def fire_anomaly(domain, resolver_ip, resolver_port):
    print(f"[{now()}] [ANOMALY ] Switching to {domain} ...")
    ok, detail = resolve(domain, resolver_ip, resolver_port)
    tag = "OK" if ok else "!!"
    print(f"[{now()}] [ANOMALY ] {tag} {domain} -> {detail}")
    if ok:
        print("            Check the Home Detector Admin UI (Alerts) for a new dns-domain alert.")


def main():
    parser = argparse.ArgumentParser(description="Trigger Home Detector's DNS anomaly detector on demand.")
    parser.add_argument("--resolver", default=DEFAULT_RESOLVER_IP,
                        help="IP of Home Detector's DNS listener (usually your Home Assistant host)")
    parser.add_argument("--port", type=int, default=DEFAULT_RESOLVER_PORT,
                        help="Port Home Detector's DNS listener is exposed on (default 53)")
    parser.add_argument("--baseline", default=",".join(DEFAULT_BASELINE_DOMAINS),
                        help="Comma-separated list of 'normal' domains to keep querying")
    parser.add_argument("--anomaly", default=DEFAULT_ANOMALY_DOMAIN,
                        help="Domain to switch to when triggered, must actually resolve, see script docstring")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, help="Seconds between baseline lookups")
    parser.add_argument("--once", action="store_true",
                        help="Skip the baseline loop, just fire one anomaly lookup and exit")
    args = parser.parse_args()

    baseline_domains = [d.strip() for d in args.baseline.split(",") if d.strip()]

    print(f"Home Detector DNS anomaly trigger")
    print(f"  Resolver : {args.resolver}:{args.port}")
    print(f"  Baseline : {baseline_domains}")
    print(f"  Anomaly  : {args.anomaly}")
    print()

    if args.once:
        fire_anomaly(args.anomaly, args.resolver, args.port)
        return

    stop_event = threading.Event()
    thread = threading.Thread(
        target=baseline_loop,
        args=(baseline_domains, args.resolver, args.port, args.interval, stop_event),
        daemon=True,
    )
    thread.start()

    print("Baseline traffic is running in the background.")
    print("Press ENTER at any time to fire the anomaly lookup, or 'q' + ENTER to quit.\n")

    try:
        while True:
            command = input()
            if command.strip().lower() in ("q", "quit", "exit"):
                break
            fire_anomaly(args.anomaly, args.resolver, args.port)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        print("\nStopping...")
        stop_event.set()
        thread.join(timeout=2)


if __name__ == "__main__":
    main()