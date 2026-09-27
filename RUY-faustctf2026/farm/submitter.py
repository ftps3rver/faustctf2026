"""FAUST flag submitter: newline-delimited TCP protocol, statuses via FlagDB."""
import socket

import config


def _classify(response_line):
    """
    Map a FAUST submission response to a status.

    Response format: "<flag> <CODE> [optional message]".
      OK  -> accepted (scores)      ACCEPTED
      DUP -> already submitted       REJECTED (terminal)
      OWN -> our own flag            REJECTED (terminal)
      OLD -> expired (>5 ticks)      REJECTED (terminal)
      INV -> invalid flag            REJECTED (terminal)
      ERR -> server error, retry     SUBMITTED (retry next tick)
    Unknown -> SUBMITTED so it gets retried.
    """
    parts = response_line.split()
    code = parts[1].upper() if len(parts) >= 2 else parts[0].upper()
    if code == "OK":
        return "ACCEPTED"
    if code in ("DUP", "OWN", "OLD", "INV"):
        return "REJECTED"
    return "SUBMITTED"  # ERR or anything unexpected -> retry


def submit_flags(flags, db):
    """Open one connection, send all flags, record per-flag responses."""
    if not flags:
        return
    try:
        sock = socket.create_connection(
            (config.SUBMIT_HOST, config.SUBMIT_PORT), timeout=config.SUBMIT_TIMEOUT)
    except Exception as e:
        print(f"[submit] connect failed: {e}")
        return
    sock.settimeout(config.SUBMIT_TIMEOUT)

    _drain_banner(sock)

    payload = b""
    if config.SUBMIT_TOKEN:
        payload += config.SUBMIT_TOKEN.encode() + b"\n"
    for flag in flags:
        db.mark(flag, "SUBMITTED")
        payload += flag.encode() + b"\n"
    try:
        sock.sendall(payload)
    except Exception as e:
        print(f"[submit] send failed: {e}")
        sock.close()
        return

    lines = _read_lines(sock)
    sock.close()
    _record(flags, lines, db)


def _record(flags, lines, db):
    """Prefer matching by echoed flag; fall back to line order."""
    remaining = list(flags)
    matched_any = False
    for line in lines:
        hit = next((fl for fl in remaining if fl in line), None)
        if hit:
            db.mark(hit, _classify(line), line)
            remaining.remove(hit)
            matched_any = True
    if not matched_any:  # server doesn't echo flags -> map by order
        for flag, line in zip(flags, lines):
            db.mark(flag, _classify(line), line)


def _drain_banner(sock, wait=0.5):
    sock.settimeout(wait)
    try:
        while sock.recv(4096):
            pass
    except socket.timeout:
        pass
    finally:
        sock.settimeout(config.SUBMIT_TIMEOUT)


def _read_lines(sock):
    buf = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return [l for l in buf.decode(errors="replace").splitlines() if l.strip()]
