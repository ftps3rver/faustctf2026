"""Target discovery: parse FAUST teams.json, fall back to IP enumeration.

teams.json shape (from official docs):
  {
    "teams": [123, 456, 789],
    "flag_ids": { "service1": { "123": ["abc","def"], "789": ["x","y"] } }
  }
Keys under flag_ids are TEAM NUMBERS. Vulnbox of team N is fd66:666:N::2.
Flag ids only appear for teams whose service is up, so use them as the
primary target list - no point attacking a service that's down.
"""
import json
import os
import ssl
import time
import urllib.request

import config


def team_ip(team):
    return config.TEAM_IP_TEMPLATE.format(team=team)


def fetch_attack_json(url=None, timeout=10):
    """Get teams.json. Prefer a locally-pushed file (the vulnbox can't reach
    the dashboard, but the Windows host pushes a fresh teams.json every tick),
    then fall back to the URL if configured/reachable."""
    import os
    # 1) local file, refreshed out-of-band by push_teams.py on the Windows host
    path = os.environ.get("FARM_TEAMS_JSON", getattr(config, "ATTACK_JSON_FILE", ""))
    if path and os.path.exists(path):
        try:
            with open(path, "rb") as f:
                data = json.loads(f.read().decode())
            age = time.time() - os.path.getmtime(path)
            if age > 400:
                print(f"[targets] WARN local teams.json is {age:.0f}s old (>2 ticks)")
            return data
        except Exception as e:
            print(f"[targets] local teams.json read failed: {e}")
    # 2) URL fallback (works only where the dashboard is reachable)
    url = url or config.ATTACK_JSON_URL
    if not url:
        return None
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"[targets] teams.json fetch failed: {e}")
        return None


def parse_targets(attack, service_filter=None):
    """Yield (service, target_ip, flag_ids) tuples from teams.json."""
    out = []
    flag_ids = (attack or {}).get("flag_ids", {})
    for service, teams in flag_ids.items():
        if service_filter and service != service_filter:
            continue
        for team, ids in teams.items():
            if _is_own(team):
                continue
            out.append((service, team_ip(team), ids))
    return out


def enumerate_targets(attack=None):
    """Fallback target list: teams.json 'teams' array, else the id range."""
    teams = (attack or {}).get("teams") if attack else None
    if not teams:
        teams = list(config.TEAM_ID_RANGE)
    out = []
    for team in teams:
        if config.OWN_TEAM_ID is not None and int(team) == int(config.OWN_TEAM_ID):
            continue
        out.append(team_ip(team))
    return out


def _is_own(team):
    return config.OWN_TEAM_ID is not None and int(team) == int(config.OWN_TEAM_ID)
