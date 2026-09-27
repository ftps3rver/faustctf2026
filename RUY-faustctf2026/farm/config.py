"""
FAUST CTF 2026 - Exploit Farm configuration.

Values below are based on the official FAUST CTF 2025 rules/setup docs, which
are stable across years. Re-verify the ones marked TODO on game day (2026-09-26)
in case anything changed. Sources:
  https://2025.faustctf.net/information/setup/
  https://ctf-gameserver.org/submission/
"""
import re

# --- Flag format (CONFIRMED) ----------------------------------------------
# FAUST flag: FAUST_ + 32 base64-ish chars.
FLAG_REGEX = re.compile(rb"FAUST_[A-Za-z0-9/+]{32}")

# --- Flag submission server (CONFIRMED for 2025) --------------------------
# Plaintext TCP. Send "<flag>\n"; server replies "<flag> <CODE> [msg]".
# Codes: OK / DUP / OWN / OLD / INV / ERR. No auth token - the VPN source IP
# identifies your team. TODO: confirm host/port unchanged for 2026.
SUBMIT_HOST = "submission.faustctf.net"
SUBMIT_PORT = 666
SUBMIT_TOKEN = ""            # not needed for FAUST; leave empty
SUBMIT_TIMEOUT = 10

# --- Attack info (teams.json) ---------------------------------------------
# FAUST exposes team numbers + flag ids here. Keys under flag_ids are TEAM
# NUMBERS (not IPs). TODO: confirm the 2026 subdomain/path is the same pattern.
ATTACK_JSON_URL = "https://2026.faustctf.net/competition/teams.json"
# The vulnbox (where the farm runs) can't reach the dashboard, so the Windows
# host pushes a fresh teams.json here every tick via push_teams.py. Read first.
ATTACK_JSON_FILE = "/root/farm/teams.json"

# Vulnbox address: team N -> fd66:666:N::2 (decimal, no hex). (CONFIRMED)
TEAM_IP_TEMPLATE = "fd66:666:{team}::2"

# Fallback only, if teams.json is unreachable. TODO: set the real max team id.
TEAM_ID_RANGE = range(1, 2)

# Our own team number - NEVER attack it. (from VPN cert: "Team 915")
OWN_TEAM_ID = 915          # our vulnbox = fd66:666:915::2, gateway-4
# NOP team (unaltered vulnbox to test exploits against): fd66:666:1::2
NOP_TEAM_ID = 1

# --- Timing (CONFIRMED for 2025) ------------------------------------------
TICK_SECONDS = 180          # 1 tick = 3 minutes
FLAG_VALID_TICKS = 5        # a flag can be submitted for 5 ticks (15 min)
# Kill a single exploit run after this many seconds (must stay < TICK_SECONDS).
EXPLOIT_TIMEOUT = 25
# Parallel exploit runs. FAUST has hundreds of teams, so keep this high.
MAX_WORKERS = 64

# --- Paths -----------------------------------------------------------------
EXPLOITS_DIR = "exploits"
DB_PATH = "farm.db"
