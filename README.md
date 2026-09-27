# RUY · FAUST CTF 2026 — Writeups & Exploits

**Team:** RUY — **rank #124** at [FAUST CTF 2026](https://2026.faustctf.net/)
(Attack/Defense) · internal team `915` (`fd66:666:915::2`)
**Members:** ftps3rver · Koated

This repository documents two attacks we ran during the game, with fully
reproducible writeups, the exact exploits we used, and the autofarm that ran them
against the whole scoreboard every tick.

---

## Services covered

| Service | Port | Class | Vulnerability | Writeup | Exploit |
|---|---|---|---|---|---|
| **Alf** | `1986` (HTTP) | LFI → RCE | Typst `read()` sandbox escape via a symlink planted through unsanitised `tar xf`; flag exfiltrated in the compiled PDF's metadata | [writeups/alf.md](writeups/alf.md) | [exploits/alf.py](exploits/alf.py) |
| **Interstellar Mission Control** | `8080` (custom TCP) | Broken Access Control / IDOR | `FETCH` ownership filter forgets the `crew != null` guard the update path has; `null == null` in Neko makes every null-crew spaceship world-readable | [writeups/imc.md](writeups/imc.md) | [exploits/imc.py](exploits/imc.py) |

Both exploits produced **accepted** flags on the live infrastructure.

---

## Repository layout

```
.
├── README.md                  # you are here
├── writeups/
│   ├── alf.md                 # Alf — arbitrary file read via Typst + tar symlink
│   └── imc.md                 # IMC — IDOR in FETCH (null-crew spaceships)
├── exploits/
│   ├── alf.py                 # standalone Alf exploit (stdlib only)
│   └── imc.py                 # standalone IMC exploit (stdlib only)
├── farm/                      # the autofarm that ran everything every tick
│   ├── farm.py                # config-driven farm: discovers exploits/, submits, dedupes (SQLite)
│   ├── farm2_alf.py           # in-process Alf+Rufflecopter farm (the one we ran Alf through)
│   ├── config.py targets.py db.py submitter.py preflight.py
│   ├── exploits/              # exploits the farm shells out to (Service__name.py)
│   └── README.md              # how to run the farm
└── srcref/                    # trimmed vulnerable source, for reference in the writeups
    ├── alf/   (main.py, typst_util.py, auth.py, Dockerfile, docker-compose.yml, ...)
    └── imc/   (fetch.neko, update.neko, create.neko, parser.neko, responder.neko, ...)
```

---

## Quick start

Each exploit is self-contained (Python 3 standard library only) and follows the
FAUST farm contract: **target host** as `argv[1]` or `TARGET_IP`, **flag ids** as
the `FLAG_IDS` env var or on stdin (JSON), flags printed to **stdout**.

```bash
# Alf — one target
FLAG_IDS='{"0":["<flag-id-uuid>"]}' python3 exploits/alf.py 'fd66:666:<TEAM>::2'

# IMC — one target (SPACESHIP fetch-all doesn't even need flag ids)
echo 'null' | python3 exploits/imc.py 'fd66:666:<TEAM>::2'
```

To run them against every team automatically (fetch `teams.json` → attack all →
submit → dedupe → loop each tick), see [farm/README.md](farm/README.md):

```bash
cd farm
python3 preflight.py     # confirm VPN routes the game net + submission server
python3 farm.py          # loop: run all exploits/, submit, dedupe in farm.db
```

> **Ethics / scope.** These exploits were run against the official FAUST CTF 2026
> competition infrastructure under the event's rules. They target intentionally
> vulnerable services in an authorized Attack/Defense setting. Do not point them
> at anything you are not authorized to test.

---

## The two bugs in one paragraph each

**Alf.** `tar xf` restores symlink members verbatim, so we drop `r -> /` next to
the `main.typ` the app compiles. Typst confines file reads to the project root
*lexically* and follows in-root symlinks without canonicalising the target
(`typst/typst#5454`), so `read("r/app/data/<id>/flag/flag.typ")` escapes to the
real filesystem. `#set document(title: read(...))` writes those bytes into the
PDF's plaintext metadata, which is returned in the HTTP response. (Same primitive
gives root file-write → optional cron RCE, off by default.)

**IMC.** `fetch.neko`'s SPACESHIP ownership filter is
`being.crew == row.crew || being.id == row.janitor`. The update path guards this
with `being.crew != null && ...`; the fetch path does not. A fresh being has
`crew == null`, the checker's flag spaceships have `crew == null` (owned via
`janitor`), and Neko evaluates `null == null` as **true** — so every flag
spaceship is readable by any newly created being. An empty descriptor makes
`FETCH` dump the whole table.

---

_Writeups by team RUY (ftps3rver, Koated) — FAUST CTF 2026._
