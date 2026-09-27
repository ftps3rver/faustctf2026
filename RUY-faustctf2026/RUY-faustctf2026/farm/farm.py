#!/usr/bin/env python3
"""
FAUST CTF 2026 - Exploit Farm (entry point).

Every tick:
  1. fetch attack.json (or enumerate targets as fallback)
  2. run each exploit in exploits/ against each target, in parallel
  3. extract flags from exploit stdout/stderr via FLAG_REGEX
  4. store new flags, then submit all pending flags

Usage:
  python farm.py            # loop forever, one pass per tick
  python farm.py --once     # single pass (for testing)
"""
import os
import sys
import glob
import time
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
import targets
from db import FlagDB
from submitter import submit_flags


def discover_exploits():
    pat = os.path.join(config.EXPLOITS_DIR, "*.py")
    return [p for p in sorted(glob.glob(pat))
            if not os.path.basename(p).startswith("_")]


def _matches(exploit, service):
    """'Service__foo.py' targets only Service; no '__' runs against everything."""
    name = os.path.basename(exploit)
    if "__" not in name:
        return True
    if not service:
        return False
    return name.split("__", 1)[0].lower() == service.lower()


def run_exploit(exploit, service, target, flag_ids):
    """Run one exploit against one target; return list of flag bytes found."""
    env = dict(os.environ)
    env["TARGET_IP"] = str(target)
    env["SERVICE"] = str(service or "")
    env["FLAG_IDS"] = json.dumps(flag_ids) if flag_ids is not None else "null"
    try:
        proc = subprocess.run(
            [sys.executable, exploit, str(target)],
            input=env["FLAG_IDS"].encode(),
            capture_output=True, timeout=config.EXPLOIT_TIMEOUT, env=env,
        )
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []
    return config.FLAG_REGEX.findall(proc.stdout + b"\n" + proc.stderr)


def build_jobs(exploits):
    """Return list of (exploit, service, target, flag_ids)."""
    attack = targets.fetch_attack_json()
    jobs = []
    parsed = targets.parse_targets(attack) if attack else []
    if parsed:
        for service, target, ids in parsed:
            for ex in exploits:
                if _matches(ex, service):
                    jobs.append((ex, service, target, ids))
    else:
        # No flag ids yet (early game) or teams.json unreachable: hit every
        # known vulnbox with every exploit.
        print("[farm] no flag ids - enumerating all vulnboxes")
        for target in targets.enumerate_targets(attack):
            for ex in exploits:
                jobs.append((ex, None, target, None))
    return jobs


def one_pass(db):
    exploits = discover_exploits()
    if not exploits:
        print("[farm] WARNING: no exploits in", config.EXPLOITS_DIR)
        return
    jobs = build_jobs(exploits)
    found = 0
    with ThreadPoolExecutor(max_workers=config.MAX_WORKERS) as pool:
        futs = {pool.submit(run_exploit, *job): job for job in jobs}
        for fut in as_completed(futs):
            ex, service, target, _ = futs[fut]
            for flag in fut.result():
                if db.add(flag.decode(), service, str(target), os.path.basename(ex)):
                    found += 1
    pending = db.pending()
    submit_flags(pending, db)
    print(f"[farm] {len(jobs)} jobs | {found} new flags | "
          f"{len(pending)} submitted | stats={db.stats()}")


def main():
    db = FlagDB(config.DB_PATH)
    once = "--once" in sys.argv
    while True:
        start = time.time()
        try:
            one_pass(db)
        except KeyboardInterrupt:
            print("\n[farm] stopped")
            break
        except Exception as e:
            print(f"[farm] pass error: {e}")
        if once:
            break
        time.sleep(max(1, config.TICK_SECONDS - (time.time() - start)))


if __name__ == "__main__":
    main()
