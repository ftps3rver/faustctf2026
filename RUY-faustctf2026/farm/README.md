# Autofarm — FAUST CTF 2026 (team RUY / 915)

Two farms are included. Both fetch `teams.json`, attack every team's vulnbox in
parallel, grep `FAUST_[A-Za-z0-9/+]{32}` flags, submit them to
`submission.faustctf.net:666`, and dedupe so nothing is re-submitted. Run them
from a shell where the **player OpenVPN** is up (the source IP is what identifies
your team to the submission server).

Everything is Python 3 **standard library only** — nothing to `pip install`.

---

## Option A — `farm.py` (recommended, config-driven, all services)

Discovers every `exploits/Service__name.py`, runs it against each team that has
that service up (per `teams.json` `flag_ids`), and records flags + submission
status in a local SQLite DB (`farm.db`).

```bash
cd farm
python3 preflight.py     # 1) confirm the game net + submission server are reachable
python3 farm.py          # 2) loop forever, one pass per tick (3 min)
python3 farm.py --once   #    or a single pass, for testing
```

- Exploits live in `farm/exploits/` and are matched by filename:
  `Alf__alf.py` → service `Alf`, `Interstellar Mission Control__imc.py` → IMC.
- Your own team (`915`) is skipped automatically (`config.OWN_TEAM_ID`).
- Flag state is in `farm.db`; `db.stats()` prints NEW/SUBMITTED/ACCEPTED/REJECTED.

### Configuration — `config.py`

| Setting | Value | Note |
|---|---|---|
| `OWN_TEAM_ID` | `915` | never attacked (from the VPN cert "Team 915") |
| `NOP_TEAM_ID` | `1` | NOP vulnbox — safe test target |
| `TEAM_IP_TEMPLATE` | `fd66:666:{team}::2` | decimal team id → IPv6 vulnbox |
| `SUBMIT_HOST:PORT` | `submission.faustctf.net:666` | plaintext TCP, VPN-IP auth |
| `ATTACK_JSON_URL` | `https://2026.faustctf.net/competition/teams.json` | scoreboard feed |
| `TICK_SECONDS` | `180` | 1 tick = 3 min; a flag is valid for 5 ticks |
| `EXPLOIT_TIMEOUT` | `25` | per-exploit kill (< tick) |
| `MAX_WORKERS` | `64` | parallel exploit runs |

> If the box running the farm cannot reach the dashboard, push a fresh
> `teams.json` to it out-of-band and point `FARM_TEAMS_JSON` (or
> `config.ATTACK_JSON_FILE`) at it; `targets.fetch_attack_json()` prefers the
> local file and falls back to the URL.

---

## Option B — `farm2_alf.py` (in-process, Alf + Rufflecopter)

This is the farm we actually ran **Alf** through: no subprocess overhead, its own
per-target timing, and a plain-text dedupe file (`farm2_seen.txt`). It also
carries the adaptive Rufflecopter attack. It never touches `farm.py`/`farm.db`, so
you can run both farms side by side (IMC on `farm.py`, Alf on `farm2_alf.py`).

```bash
cd farm
python3 farm2_alf.py               # loop Alf + Rufflecopter every 120 s
python3 farm2_alf.py --service Alf # Alf only
python3 farm2_alf.py --once        # single pass
```

The Alf path template baked into `farm2_alf.py` is the live winner
`/app/data/{F}/flag/flag.typ`; adjust `ALF_TMPL` if a round moves the file.

---

## Typical split we ran

```bash
# terminal 1 — VPN up here
sudo openvpn --config player-faustctf.conf

# terminal 2 — IMC (+ any Service__name.py exploit) via the SQLite farm
cd farm && python3 farm.py

# terminal 3 — Alf via the in-process farm
cd farm && python3 farm2_alf.py --service Alf
```

## Submission protocol (reference)

Plain TCP to `submission.faustctf.net:666`. Read the banner (up to a blank line),
send `"<flag>\n"` (one or many), read `"<flag> <CODE> [msg]"` lines. Codes:
`OK` (scores), `DUP`/`OWN`/`OLD`/`INV` (terminal — don't retry), `ERR` (retry).
No token; your VPN source IP is your identity.
