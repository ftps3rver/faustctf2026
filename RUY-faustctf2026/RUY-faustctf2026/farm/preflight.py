#!/usr/bin/env python3
"""
Run this FIRST in your VSCode terminal (the same shell where your player VPN is
up). It tells you whether you can attack directly from this machine, or whether
the farm must run on the vulnbox instead.

    python3 preflight.py

Checks:
  1. teams.json reachable (dashboard)                -> picks live targets
  2. IPv6 game-net reachable (connect to a live team's service port)
  3. submission server reachable (submission.faustctf.net:666)

If 2 and 3 both PASS -> run `python3 farm.py` right here in VSCode.
If they FAIL         -> your VPN isn't routing the game net here; run the farm
                        on the vulnbox instead (see README_RUN.md).
"""
import json
import socket
import ssl
import sys
import urllib.request

import config

SERVICE_PORTS = {
    "Alf": 1986,
    "Interstellar Mission Control": 8080,
    "Rufflecopter": 35244,
}


def ok(msg):  print(f"  [PASS] {msg}")
def bad(msg): print(f"  [FAIL] {msg}")


def tcp_check(host, port, timeout=6):
    """IPv6/IPv4-safe TCP connect test."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return False, f"DNS/addr error: {e}"
    last = "no address"
    for family, stype, proto, _, sa in infos:
        try:
            s = socket.socket(family, stype, proto)
            s.settimeout(timeout)
            s.connect(sa)
            s.close()
            return True, f"connected {sa[0]}:{port}"
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
    return False, last


def main():
    print("== FAUST farm preflight ==\n")

    # 1) teams.json
    print("1) teams.json / attack info")
    attack = None
    try:
        ctx = ssl.create_default_context()
        raw = urllib.request.urlopen(config.ATTACK_JSON_URL, timeout=12, context=ctx).read()
        attack = json.loads(raw)
        svcs = {s: len(t) for s, t in attack.get("flag_ids", {}).items()}
        ok(f"fetched: {len(attack.get('teams', []))} teams, flag_ids={svcs}")
    except Exception as e:
        bad(f"cannot fetch {config.ATTACK_JSON_URL}: {e!r}")
        print("     (farm can still read a locally-pushed teams.json on the vulnbox)")

    # 2) IPv6 game-net: connect to a live team's service port
    print("\n2) game-net reachability (IPv6 to a live team)")
    net_ok = False
    if attack:
        fid = attack.get("flag_ids", {})
        for svc, port in SERVICE_PORTS.items():
            teams = [t for t in fid.get(svc, {}) if int(t) != int(config.OWN_TEAM_ID)]
            if not teams:
                continue
            team = sorted(teams, key=lambda x: int(x))[0]
            host = config.TEAM_IP_TEMPLATE.format(team=team)
            good, detail = tcp_check(host, port)
            if good:
                ok(f"{svc} team {team} [{host}]:{port} -> {detail}")
                net_ok = True
                break
            else:
                bad(f"{svc} team {team} [{host}]:{port} -> {detail}")
    else:
        # no attack info: try the NOP team box directly
        host = config.TEAM_IP_TEMPLATE.format(team=config.NOP_TEAM_ID)
        good, detail = tcp_check(host, 8080)
        (ok if good else bad)(f"NOP [{host}]:8080 -> {detail}")
        net_ok = good

    # 3) submission server
    print("\n3) submission server")
    good, detail = tcp_check(config.SUBMIT_HOST, config.SUBMIT_PORT)
    (ok if good else bad)(f"{config.SUBMIT_HOST}:{config.SUBMIT_PORT} -> {detail}")
    submit_ok = good

    # verdict
    print("\n== VERDICT ==")
    if net_ok and submit_ok:
        print("  THIS MACHINE can attack. Run the farm right here in VSCode:")
        print("      python3 farm.py            # loop every tick, auto-submit")
        print("      python3 farm.py --once     # one pass, then stop")
    else:
        print("  This machine can NOT fully reach the game net/submission.")
        print("  Run the farm on the vulnbox instead:")
        print("      python3 deploy_and_run.py  # pushes farm to vulnbox & runs it")
        print("  (Make sure your player VPN is UP in THIS shell and retry preflight.)")
    return 0 if (net_ok and submit_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
