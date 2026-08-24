# AmIWeak

[![CI](https://github.com/miichoow/amiweak/actions/workflows/ci.yml/badge.svg)](https://github.com/miichoow/amiweak/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/miichoow/amiweak/branch/main/graph/badge.svg)](https://codecov.io/gh/miichoow/amiweak)
[![Python versions](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/downloads/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://www.mypy-lang.org/static/mypy_badge.svg)](https://mypy-lang.org/)

A web page and a REST API that answer one question: is this password already
known to attackers?

Four signals go into the answer.

| Signal | Source | Where it runs |
|---|---|---|
| Has it been breached? | [Have I Been Pwned](https://haveibeenpwned.com/Passwords) | Server |
| Is it in a cracking wordlist? | [weakpass](https://weakpass.com/) | Server |
| Is it easy to guess? | [zxcvbn-ts](https://github.com/zxcvbn-ts/zxcvbn) | Browser + server |
| Is it specific to your org? | custom denylist | Server |

The two network lookups run at the same time, so a check costs the slower of
the two round trips rather than their sum. The denylist joins the same fan-out
but never leaves the process: it is a dict lookup against a digest set built
at startup. Strength scoring happens locally as you type, and again server-side
when `POST /api/v1/check` is submitted, using the identical vendored bundles in
both places so the two never disagree.

HIBP and weakpass both answer for two digest algorithms, SHA-1 and NTLM; see
[NTLM support](#ntlm-support) below. The denylist is SHA-1 only.

## The password never gets logged

Everything else in the design bends around this one.

The plaintext reaches exactly three places, all of them inside this deployment:
the route handler's local, `CheckRunner.evaluate`, and, when strength scoring
is on, the Node worker's stdin, which is a pipe to a child process on the same
host. `evaluate` scores it, measures it, tests it against the denylist tokens,
hashes it, and drops it; every checker downstream of `sha1_hex` sees a digest
and nothing else. Only the hash prefix leaves the machine: five characters to
HIBP, six to weakpass. Both providers
answer with every hash sharing that prefix, so neither one learns which you asked
about. HIBP also gets `Add-Padding: true`, which pads the response to a uniform
size so its length can't fingerprint the prefix either.

Redaction is installed as a log record factory rather than a filter, and that
distinction matters more than it sounds. A filter on the root logger only catches
records emitted on the root logger. It does nothing at all for
`amiweak.routes.api`, because `callHandlers` walks ancestors' handlers but skips
their filters. The factory runs when the record is constructed, before any
handler exists to route around it. So a `logger.debug(request.json)` added a year
from now still can't print a secret.

Exception messages get stripped out of tracebacks before a handler sees them.
`RuntimeError(f"bad password {password}")` is all it takes to leak one, and the
frames (file, line, source text) are the part you actually wanted anyway.

Two smaller things. The Werkzeug debugger is force-disabled no matter what
`FLASK_DEBUG` says, because it is an interactive Python console and it has no
business sitting behind a form that receives passwords. And every response is
`Cache-Control: no-store`, while the gunicorn access log format in
`gunicorn.conf.py` uses `%(U)s`, the path without its query string. (Werkzeug's
dev-server log has no such format hook, so there the record factory's redaction
is the only thing standing between a stray query string and the log.) Every
response also carries `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and
`Content-Security-Policy: default-src 'self'; base-uri 'none'; form-action
'none'; object-src 'none'; frame-ancestors 'none'`.

`tests/test_no_leak.py` asserts all of the above on every run. If it goes red,
fix the source. Never the assertion.

### What this does not protect against

Whoever runs the server can see what gets posted to it. A check tells you a
password isn't already public; it doesn't tell you it's safe to hand to a
stranger. Your TLS terminator sees the request. HIBP and weakpass see your
server's IP and a five-character hash prefix. And honestly, a password you have
just typed into some website is a password you might want to change regardless.

### NTLM support

Both server-side backends also answer NTLM prefix queries. Nothing in this
codebase computes an NTLM digest, though. There is no MD4 anywhere here: it's
absent from `hashlib` on OpenSSL 3 builds, and the cleanest way around that
problem is to not need it. The batch endpoint takes a digest, not a password,
so an NTLM check never involves plaintext at any point: not in the request,
not in a route-handler local, not anywhere. `POST /api/v1/check` still only
accepts SHA-1, since it hashes the plaintext it's handed itself.

## Install

AmIWeak is a server, not a library: deploy it from a checkout rather than from
a package index.

```bash
git clone https://github.com/miichoow/amiweak.git
cd amiweak
python -m venv venv
venv/bin/pip install -e ".[dev]"          # Windows: .\venv\Scripts\pip
venv/bin/pip install -e ".[dev,linux]"    # adds gunicorn
venv/bin/pip install -e ".[dev,security]" # adds semgrep, kept separate since
                                           # its dependency pins otherwise force
                                           # pip into slow backtracking against dev
```

Node.js must also be on `PATH`. Strength scoring (`POST /api/v1/check`'s
`weak` verdict) runs the vendored `zxcvbn-ts` bundles under a Node child
process, so the server and the page always agree on a password's score. Set
`strength.enabled: false` to run without Node.

`hcrulepy` and `filelock` are regular Python dependencies pulled in by
`pip install -e .`, no extra setup, and no hashcat binary of any kind is
required or present. See [Organisational denylist](#organisational-denylist).

## Run

Linux, production:

```bash
gunicorn -c gunicorn.conf.py wsgi:app
```

Windows, or anywhere without gunicorn:

```bash
python run.py --config config.yaml --port 8080
```

`run.py` uses Werkzeug's single-process server. Fine for development, and it
should not face the internet. `--host` and `--port` override the configured
bind address; `--cert` and `--key`, which must be given together, serve over
HTTPS instead:

```bash
python run.py --cert cert.pem --key key.pem --port 8443
```

Config is found in this order: `--config`, then `$AMIWEAK_CONFIG`, then
`./config.yaml`. A missing file is not an error; you get the built-in defaults.

The OpenAPI document is found the same way: `$AMIWEAK_OPENAPI`, then
`./openapi.yaml`. Set it for a deployment that does not run from the
repository root. It is only consulted when `docs.enabled` is true.

## Configuration

Everything lives in `config.yaml`. Every scalar can also be set from the
environment: uppercase the path and join the levels with a double underscore.

```bash
AMIWEAK_SERVER__PORT=9000
AMIWEAK_CHECKS__HIBP__ENABLED=false
AMIWEAK_MESSAGES__LEAKED="Change this password before you do anything else."
```

Environment values win over the file. An unknown key is a startup error rather
than a warning, on the theory that a typo'd `enabld: false` quietly leaving a
check running is worse than a crash.

Three variables live under the prefix without naming a configuration key, and
are exempt from that rule: `AMIWEAK_CONFIG` and `AMIWEAK_OPENAPI`, which say
where those two files are, and `AMIWEAK_WORKERS`, which `gunicorn.conf.py`
reads to size the worker pool (default `4`).

### Reference

| Key | Default | What it does |
|---|---|---|
| `server.host` | `127.0.0.1` | Bind address (dev server) |
| `server.port` | `8080` | Bind port |
| `proxy.http` / `proxy.https` | `null` | Outbound proxy for the two upstream APIs |
| `proxy.no_proxy` | `null` | Hosts to reach directly |
| `http.timeout` | `5.0` | Per-request timeout, seconds. Every check inherits it unless it sets its own |
| `http.verify_tls` | `true` | Leave this on |
| `http.ca_bundle` | `null` | PEM to trust instead of certifi |
| `http.user_agent` | `AmIWeak/1.0` | Sent upstream |
| `checks.<name>.enabled` | `true` | Turn a backend off entirely |
| `checks.<name>.timeout` | `null` | That backend's request timeout; `null` inherits `http.timeout` |
| `checks.<name>.on_error` | `fail_open` | `fail_open` or `fail_closed`, see below |
| `checks.<name>.algorithms` | `[sha1, ntlm]` | Which algorithms this backend answers for; `denylist` defaults to `[sha1]` only |
| `policy.overall_deadline` | `8.0` | Seconds for the whole fan-out |
| `policy.min_length` | `8` | Plaintext only (`/api/v1/check`); unenforceable on hash endpoints |
| `policy.rate_limit.enabled` | `true` | Per-IP limiting, shared by `/api/v1/check` and `/api/v1/check/hash` |
| `policy.rate_limit.requests` | `30` | Allowance per window |
| `policy.rate_limit.per_seconds` | `60` | Window length |
| `batch.enabled` | `true` | Whether `/api/v1/check/batch` answers requests; `false` returns 404 rather than advertising a disabled route |
| `batch.max_items` | `1000` | Items per request; 400 above this |
| `batch.max_concurrency` | `8` | In-flight upstream requests per batch |
| `batch.deadline` | `120.0` | Seconds for the whole batch; raise with `max_items` |
| `batch.max_label_length` | `128` | Longest accepted label |
| `batch.rate_limit.enabled` | `true` | Whether the batch prefix allowance is enforced at all |
| `batch.rate_limit.prefixes` | `5000` | Unique uncached prefixes per window |
| `batch.rate_limit.per_seconds` | `3600` | Window length |
| `cache.enabled` | `true` | Whether parsed ranges are cached |
| `cache.max_entries` | `256` | Cached ranges; ~40-60 MB per worker |
| `cache.ttl_seconds` | `3600` | How long a cached range stays valid |
| `state.path` | `null` | SQLite file shared by rate-limit buckets and metric counters; `null` keeps per-worker state, see below |
| `state.busy_timeout` | `5.0` | Seconds a worker waits for the SQLite writer lock before falling back to per-worker state |
| `denylist.path` | `null` | Word file for the org denylist; `null` turns the whole feature off |
| `denylist.min_token_length` | `4` | Shortest *normalized* entry `Denylist` will accept (after casefold, l33t-decode, and stripping punctuation); an entry that normalizes shorter is a startup error |
| `denylist.match_plaintext` | `true` | Whether `/api/v1/check` gates on substring matches against plaintext |
| `denylist.rules` | `[rules/corporate.rule]` | hashcat rule files expanded via `hcrulepy`; `[]` disables expansion |
| `denylist.max_digests` | `1000000` | Abort-during-generation ceiling on the expanded digest set |
| `denylist.cache_path` | `null` | Persistent digest cache file; `null` → `<path>.amwk-digests` beside the dictionary |
| `strength.enabled` | `true` | Whether the page *and* `/api/v1/check` gate on zxcvbn-ts |
| `strength.min_score` | `3` | zxcvbn-ts score 0-4 required to pass |
| `strength.timeout` | `2.0` | Seconds to wait for the Node scoring worker |
| `messages.*` | see file | Every string a user sees |
| `messages.batch_complete` | see file | `{total}` and `{failed}` placeholders |
| `messages.denylisted` | see file | Shown when the denylist gate or checker fires |
| `logging.level` | `INFO` | Root log level |
| `logging.access_log` | `true` | Silence Werkzeug's request log when false |
| `docs.enabled` | `true` | Serve `/docs` and `/api/v1/openapi.json`. Both 404 when false |
| `ui.theme` | `original` | Which design the page is served in. See below |

### Themes

`ui.theme` picks the look of `/`. Only the look changes: same markup contract,
same API, same client-side scoring, same headers.

| Theme | Look |
|-------|------|
| `original` | The default. Aurora gradient over a glass card, dark first |
| `vault` | Institutional. Solid surfaces, vault blue, full light and dark palettes |
| `terminal` | Security-scanner CLI. Monospace, phosphor green on black, dark only |
| `editorial` | Oversized serif headline, hairline rules, one accent. Print-calm |
| `bento` | Dark dashboard. One tile per idea, gradient on the CTA only |

An unknown name fails at startup rather than falling back silently. Every
theme's fonts are vendored under `static/vendor/fonts`, so no page reaches a
third-party origin and the CSP stays `default-src 'self'`.

To compare them side by side, `python design-preview/serve.py` runs all five at
once on ports 8090–8094; see `design-preview/README.md`.

### The outbound session

One `requests.Session` is shared by every backend, so proxy and TLS settings
cannot drift apart between them. Two of its properties are worth knowing.

**It ignores the environment.** `session.trust_env = False`, so
`REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `HTTP_PROXY`, `HTTPS_PROXY` and
`NO_PROXY` have no effect on AmIWeak's outbound calls. `requests` otherwise
lets those silently override `session.verify` and `session.proxies` on any call
that does not pass `verify=` explicitly, which would defeat the point of
centralising the settings here, and would mean a machine-level variable could
quietly turn verification off. Configure proxies and CA bundles through
`config.yaml` (`proxy.*`, `http.ca_bundle`); nothing else is read.

**It retries once.** `https://` requests get one retry with a 0.2 s backoff, on
502, 503 and 504 only, GET only. So a backend that is down can cost up to twice
`checks.<name>.timeout` before it reports `timeout`; size
`policy.overall_deadline` with that in mind.

**Timeouts inherit.** `http.timeout` is the one every backend uses;
`checks.<name>.timeout` ships as `null`, meaning "inherit", and a number there
overrides it for that backend alone. So raising `http.timeout` to `10.0` raises
it everywhere, while

```yaml
http:
  timeout: 5.0
checks:
  weakpass:
    timeout: 10.0
```

gives weakpass longer and leaves HIBP at five seconds. Inheritance is resolved
once, at startup, so a `CheckConfig` always carries a real number; nothing
downstream has to know a value was inherited.

### If your network terminates TLS

Corporate interception makes `requests` fail where a browser succeeds, because
`requests` trusts certifi and your browser trusts the system store. Export your
CA and point `http.ca_bundle` at it:

```yaml
http:
  ca_bundle: /etc/ssl/certs/corporate-root.pem
```

Reach for that instead of `verify_tls: false`. You keep verification, you just
verify against a different root.

### fail_open vs fail_closed

When a backend can't be reached, `fail_open` computes the verdict from whichever
checks did answer and sets `degraded: true` in the response. `fail_closed` makes
the whole verdict `error` instead.

`fail_open` is the default, and it has a sharp edge worth knowing about. If both
backends are down, a genuinely breached password comes back as `safe` with
`degraded: true`. The page shows the degraded note, but anything consuming the
API should check that flag rather than trusting the verdict alone. Set
`fail_closed` if a wrong "safe" is worse for you than a hard failure.

### Sharing state across workers

`state.path` defaults to `null`, and with it unset the application behaves
exactly as it did before this option existed: every gunicorn worker keeps its
own rate-limit buckets and its own metric counters, in memory, gone on
restart. Nothing below changes anything for a deployment that leaves this
alone.

The case it exists for is the four workers `gunicorn.conf.py` ships as its
default (`workers = 4`, four `gthread` workers of four threads each). With
`state.path` unset, `policy.rate_limit.requests: 30` doesn't mean 30 requests
a minute for the deployment; it means roughly 30 per worker, so somewhere
close to 120 in aggregate depending on which worker a given connection lands
on. A `/metrics` scrape has the same problem in reverse: it sees whichever
worker answered the scrape, not the other three. Set `state.path` to a file,
e.g. `"amiweak-state.db"`, and every worker opens the same SQLite database
instead: a relative path resolves against the working directory the process
was started from, the same rule `denylist.path` already follows, so the two
path settings in this file don't quietly disagree about where "here" means.
`state.busy_timeout` (default `5.0`) bounds how long a worker will wait for
the SQLite writer lock before giving up on the shared store for that
operation.

What moves into the shared file: the token buckets behind `policy.rate_limit`
and `batch.rate_limit`, and the counters `/metrics` reports. The two rate
limiters keep separate allowances even though they now share one file; each
is stored under its own namespace prefix, so a client burning through the
interactive limit hasn't touched the batch limit at all, same as today.

What stays per worker on purpose: the prefix cache (`cache.py`). A cached
entry is a parsed range, tens to hundreds of kilobytes of Python objects, and
shipping one of those through an out-of-process store on every lookup would
cost more than just eating the cache miss and refetching the range. So
`cache.max_entries` and its per-worker memory multiplier are unaffected by
this setting (see the note under Monitoring below, still accurate as
written).

The shared token bucket reads `time.time()` rather than
`time.monotonic()`, because a monotonic clock has no shared epoch across
separate processes: a value one worker's clock produced means nothing to
another worker's. The cost is that an NTP correction stepping the wall clock
backwards can briefly grant a bit of extra allowance. Acceptable for a
limiter whose job is stopping casual hammering, not standing up to a
determined attacker.

If the SQLite file can't be reached for a given operation (locked past
`busy_timeout`, disk full, whatever), `ResilientStore` falls back to an
in-process `MemoryStore` for that call and counts it in `store_errors_total`,
visible on `/metrics`. That fallback is not "no limit" or "no counters"; it's
exactly the per-worker behaviour every deployment already has without
`state.path` set at all. A degraded shared store is a return to today's
baseline, not a hole opening up beneath it.

Enabling `state.path` also changes what survives a restart: rate-limit bucket
keys are client addresses, so the SQLite file ends up holding a persistent,
on-disk record of client IP addresses that outlives the process, where
before they existed only in a worker's memory and vanished the moment it
restarted. Place the file somewhere with filesystem permissions and retention
appropriate for that kind of data in your environment, the same way you would
for any other file holding client IPs.

One thing sharing the store does not fix: `uptime_seconds` in `/healthz` and
`/metrics` stays per worker even when `state.path` is set. A shared store has
no way to tell "this worker started 20 seconds ago" apart from "this row is
left over from last week's run" without a boot marker, and the process that
would need to write one differs between gunicorn's master and `run.py`. This
is a documented limitation, not an oversight: don't read a small
`uptime_seconds` on a shared-state deployment as a crash you missed.

## Organisational denylist

HIBP, weakpass and zxcvbn-ts are all global signals. None of them knows
`ACME2026!` is exactly the password an attacker targeting this organisation
would try first: it has never been breached, no public cracking corpus is
built around one government IT centre's initials, and zxcvbn scores it well
because it has length, mixed case, a digit run and a symbol. The denylist
closes that gap with a list only the organisation can write.

**The whole feature is off unless `denylist.path` is set.** A `null` path (the
default) skips loading, wires nothing into `CheckRunner`, and touches no cache
file.

When it's on, `denylist.path` points at a plain text file: one entry per line,
`#` starts a comment, blank lines are ignored. Entries are words like `acme`,
`widget`, project codenames, service-account conventions, whatever an
attacker who knows this organisation would try. An entry shorter than
`denylist.min_token_length` (default `4`) is a startup error rather than a
silent skip, because a two- or three-character entry would substring-match
nearly every password.

`denylist.txt.example` ships as a starting point: copy it to `denylist.txt`
and point `denylist.path` at the copy. `.gitignore` already excludes
`denylist.txt` and the generated `*.amwk-digests` sidecars, because entries may
themselves be known-bad passwords and the file is a secret.

That file feeds two layers. `/api/v1/check` gets a plaintext substring gate:
normalize the submitted password (casefold, l33t-decode, strip punctuation)
and test each entry as a substring, so `ACME-2026!` and `Ac1e2026` both match
`acme`. Every endpoint, including the digest-only ones, also gets a SHA-1
`DenylistChecker` fed by rule-expanded digests of the same entries; see
[Endpoint behaviour](#endpoint-behaviour-and-its-asymmetry) below for how those
two layers diverge.

### Rule expansion, without a hashcat binary anywhere

`denylist.rules` lists hashcat rule files (`rules/corporate.rule` ships as the
default) that get run over every entry through
[`hcrulepy`](https://github.com/miichoow/hcrulepy), a pure-Python
reimplementation of hashcat's rule engine. Each expansion is hashed into the
digest set too, so the checker matches "the org's words as an attacker would
actually try them": case variants, year and digit suffixes, l33t
substitutions, not just the literal strings typed into the file.

No hashcat binary is present anywhere in this deployment, or in the pipeline
that builds it. `hcrulepy`'s correctness is anchored to committed hashcat
capture data instead, so the rule semantics stay traceable to real hashcat
without a password-cracking binary sitting on a government server. An unknown
rule command raises `InvalidRule`, which is a startup error, same as a
missing dictionary or rule file.

The shipped `rules/corporate.rule` is 22 rules and a deliberately safe subset:
no `x`/`O` range operations, no `X ( ) = % ~ ?C`. `hcrulepy` marks those
unconfirmed against hashcat on short words, and a corporate word list is mostly
short words. Point `denylist.rules` at your own file if you want the rest;
that is a supported choice, not a guarded one, but the expansion count (and so
the generation time and `max_digests` headroom) climbs quickly with it.

### The persistent digest cache

Rule expansion is the expensive part: a few hundred entries against a real
rule file can be tens of thousands to millions of candidate digests, each one
SHA-1'd. Recomputing that on every `create_app()`, once per gunicorn worker, on
every restart, does not scale past `rules/corporate.rule`. So the generated
digest set is cached on disk, next to the dictionary, and only regenerated
when its inputs actually change.

The cache lives in a sidecar file, `<denylist.path>.amwk-digests` by default
(override with `denylist.cache_path`). It's keyed on a fingerprint:
a SHA-256 over the dictionary's exact bytes, each configured rule file's exact
bytes, the installed `hcrulepy` version, and an internal generator-version
constant, computed fresh on every start. If the fingerprint on disk matches,
the cache loads and no rule engine ever runs. If it doesn't (first start, an
edited dictionary, an edited rule file, an `hcrulepy` upgrade), generation runs
once and the result is written back.

So the first start after a change pays the generation cost; every start after
that just loads a file. With several gunicorn workers starting cold together,
generation is serialized by a `filelock` on a `.lock` sibling: one worker
generates while the rest block, then re-check the fingerprint and take the
fast path once the file lands. The write itself is atomic: a temp file,
`fsync`, `os.replace()`, so no worker, sibling or otherwise, ever reads a
half-written cache. A cache file that fails a structural check (bad magic,
wrong format version, a body length that doesn't match its own digest count)
is treated exactly like a fingerprint miss and regenerated; it never crashes
the app and never silently loads a short digest set.

`denylist.max_digests` (default `1000000`) is enforced while generation is
still running, not after: the set is capped as it's being built, so an
oversized rule file aborts as a startup error instead of exhausting memory on
the way to finding out.

### Endpoint behaviour, and its asymmetry

| Verdict | `/check` | `/check/hash` | `/check/batch` |
|---|---|---|---|
| `safe`, `leaked`, `precomputed` | yes | yes | yes |
| `too_short`, `weak` | yes | no | no |
| `denylisted` | token match | SHA-1 digest match | SHA-1 digest match |

The same password can resolve `denylisted` on `/api/v1/check` and `safe` on
`/api/v1/check/hash`: `ACME2026!` is caught on the interactive endpoint
because the server holds the plaintext and can substring-match it directly,
but on the digest endpoints it's only caught if rule expansion happened to
generate that exact candidate string. That's inherent to hashing rather than
a bug, and it will surprise someone the first time they compare the two
endpoints side by side.

`POST /api/v1/check/batch`'s `summary` object gains a `denylisted` key
alongside `leaked`, `precomputed`, `safe` and `error`, worth knowing if you
already parse that shape.

## REST API

### POST /api/v1/check

```bash
curl -X POST http://localhost:8080/api/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"password": "password"}'
```

```json
{
  "error": true,
  "errorMessage": "This password has appeared in a known data breach.",
  "verdict": "leaked",
  "degraded": false,
  "checks": [
    {"name": "hibp", "enabled": true, "applicable": true, "hit": true, "count": 52372427, "error": null},
    {"name": "weakpass", "enabled": true, "applicable": true, "hit": true, "count": null, "error": null},
    {"name": "denylist", "enabled": false, "applicable": true, "hit": null, "count": null, "error": null}
  ]
}
```

A password nothing knows about:

```json
{
  "error": false,
  "errorMessage": "This password looks fine.",
  "verdict": "safe",
  "degraded": false,
  "checks": [
    {"name": "hibp", "enabled": true, "applicable": true, "hit": false, "count": null, "error": null},
    {"name": "weakpass", "enabled": true, "applicable": true, "hit": false, "count": null, "error": null},
    {"name": "denylist", "enabled": false, "applicable": true, "hit": null, "count": null, "error": null}
  ]
}
```

`checks` carries one entry per configured backend, always, in `config.yaml`
order, including backends that are switched off. The examples here run the
shipped defaults, where `denylist.path` is `null`, so `denylist` reports
`enabled: false` and a `hit` of `null` rather than being absent. A client
should key on `name` and read `enabled`/`applicable` rather than assume a
length or a position. On a deployment that *does* configure the denylist, that
entry reads `enabled: true`, and `applicable: false` on an NTLM request, since
`checks.denylist.algorithms` is `[sha1]` by default.

`error` is true whenever the password failed a check. `errorMessage` is the
configured message for the resolved verdict. `verdict` is one of `safe`,
`leaked`, `precomputed`, `denylisted`, `too_short`, `weak`, `error`. When
`degraded` is `true`, the envelope also carries a `degradedMessage` field
(`messages.degraded`), so a client can show why the result is incomplete
without hardcoding that copy itself.

`weak` is resolved server-side, by running the same vendored `zxcvbn-ts`
bundles the page uses (see [Configuration](#configuration)'s
`strength.min_score`) under a Node child process -- not a separate Python
scoring engine, so the API and the page never disagree about whether a
password is easy to guess. It takes priority over `too_short`: a password
below `strength.min_score` is rejected before its length is even checked,
mirroring the page, which scores locally before it ever calls this endpoint.
If scoring can't run (Node missing, worker crashed or timed out), the check
falls back to the pre-scoring behavior with `degraded: true` set, the same
way an unreachable HIBP or weakpass lookup degrades today.

The status code is 200 for any completed evaluation, since a leaked password is a
successful check rather than an HTTP error. 400 means a malformed body, or a
misconfiguration where no enabled backend supports SHA-1 (the algorithm this
endpoint always hashes as); without that guard an unreachable check would
silently resolve to `safe`. 429 a rate limit, 500 an internal failure. All of
them use the same two-key envelope, so a client only ever parses one shape.

It's a POST because a GET would put the password in a URL, and URLs end up in
access logs, proxy logs, browser history, and `Referer` headers.

One boundary worth stating plainly: `/check/hash` and `/check/batch` can never
produce a `weak` verdict. Both take a digest, never plaintext, so there is no
password for the Node worker to score -- the same reasoning that keeps
`too_short` off those endpoints (see below). `POST /api/v1/check` is the only
route that receives plaintext, which is also why it's the only route that runs
the Node worker at all: adding a second, independent zxcvbn implementation to
score a digest would just be two scoring engines that disagree with each
other, the same problem running the identical bundle server-side was meant to
avoid in the first place.

### POST /api/v1/check/batch

```bash
curl -X POST http://localhost:8080/api/v1/check/batch \
  -H 'Content-Type: application/json' \
  -d '{
        "algorithm": "ntlm",
        "items": [
          {"label": "jdoe", "hash": "8846f7eaee8fb117ad06bdd830b7586c"},
          {"label": "asmith", "hash": "9f5b2c7e1a4d6083f01c9e7b5a3d2f10"}
        ]
      }'
```

```json
{
  "error": false,
  "errorMessage": "Checked 2 passwords.",
  "algorithm": "ntlm",
  "degraded": false,
  "summary": {"total": 2, "leaked": 1, "precomputed": 0, "denylisted": 0, "safe": 1, "error": 0},
  "results": [
    {
      "label": "jdoe",
      "verdict": "leaked",
      "degraded": false,
      "checks": [
        {"name": "hibp", "enabled": true, "applicable": true, "hit": true, "count": 9545824, "error": null},
        {"name": "weakpass", "enabled": true, "applicable": true, "hit": true, "count": null, "error": null},
        {"name": "denylist", "enabled": false, "applicable": true, "hit": null, "count": null, "error": null}
      ]
    },
    {
      "label": "asmith",
      "verdict": "safe",
      "degraded": false,
      "checks": [
        {"name": "hibp", "enabled": true, "applicable": true, "hit": false, "count": null, "error": null},
        {"name": "weakpass", "enabled": true, "applicable": true, "hit": false, "count": null, "error": null},
        {"name": "denylist", "enabled": false, "applicable": true, "hit": null, "count": null, "error": null}
      ]
    }
  ]
}
```

This exists for the same job `/api/v1/check` does one at a time, aimed at
auditing a batch of NTLM hashes pulled from Active Directory. It is hash-only:
there is no `password` field, and no code path in this handler that could parse
one. That is deliberate rather than incidental. A list of plaintext passwords in
transit is exactly the artifact this whole project exists to avoid, and an
endpoint that has no field to put one in can't be talked into accepting one by
mistake.

The top-level `error` describes whether the *request* was valid, not what the
checks found: a batch full of leaked passwords is still a successful batch, so
`error` stays `false` and you read `summary` and each item's `verdict` for the
actual findings. `400` means a malformed body, or an `algorithm` no enabled
backend supports; see the `/api/v1/check/hash` section below for why that
rejection exists; the same guard now applies to `/api/v1/check` and
`/api/v1/check/hash` too, so no digest-taking route can silently answer `safe`
for an algorithm nothing looked at. The per-item detail lives in `results`
once you're past that.

Result order is not guaranteed to match the order items were submitted, so a
caller joins the response back to its own records on `label`, not position.

Note that `too_short` is absent from `summary` and can never appear as a
`verdict` here, unlike on `/api/v1/check`. `policy.min_length` is a check
against plaintext length, and a digest doesn't carry a length that means
anything: a SHA-1 hash of `"a"` and a SHA-1 hash of a forty-character password
are both forty hex characters. Nothing about the digest tells you the password
was too short to bother with, so this endpoint doesn't ask.

`weak` is absent for the same underlying reason: scoring a password needs the
password, and this endpoint never receives one, only a digest.

A label is echoed back untouched and is never logged, same guarantee as the
password on the interactive endpoint. This matters for a different reason here,
though: on an AD audit the label is very likely a username or SAM account name,
and a log line pairing a username with `verdict: leaked` is a target list. Keep
labels out of anything that persists.

### POST /api/v1/check/hash

```bash
curl -X POST http://localhost:8080/api/v1/check/hash \
  -H 'Content-Type: application/json' \
  -d '{"hash": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"}'
```

```json
{
  "error": true,
  "errorMessage": "This password has appeared in a known data breach.",
  "verdict": "leaked",
  "algorithm": "sha1",
  "degraded": false,
  "checks": [
    {"name": "hibp", "enabled": true, "applicable": true, "hit": true, "count": 52372427, "error": null},
    {"name": "weakpass", "enabled": true, "applicable": true, "hit": true, "count": null, "error": null},
    {"name": "denylist", "enabled": false, "applicable": true, "hit": null, "count": null, "error": null}
  ]
}
```

`/api/v1/check` with the hashing moved to your side of the wire. Same envelope,
same verdicts, plus an echoed `algorithm`; the difference is that the plaintext
password never leaves the caller. Use this when you have a digest and no
plaintext, or when you'd rather not transmit one.

`algorithm` is optional and defaults to `"sha1"`. Ask for NTLM explicitly:

```bash
curl -X POST http://localhost:8080/api/v1/check/hash \
  -H 'Content-Type: application/json' \
  -d '{"hash": "8846f7eaee8fb117ad06bdd830b7586c", "algorithm": "ntlm"}'
```

The digest is case-insensitive and must be exactly 40 hex characters for
`sha1` or 32 for `ntlm`; anything else is a `400`. So is an algorithm no
enabled backend can answer for: if you set `algorithms: [sha1]` on both
backends, an NTLM request is rejected rather than silently answered `safe`.

Unlike `/api/v1/check/batch`, `error` here follows the **verdict**, not the
request: `true` for `leaked`, `precomputed`, and `error`, matching
`/api/v1/check`. A single check answers "is this password bad?", so that is what
the field means.

Rate limiting comes out of `policy.rate_limit`, the same bucket
`/api/v1/check` uses, at one token per request; the two endpoints are the same
amount of work and share one allowance per client IP. A `400` costs nothing,
because the body is validated before the limiter is charged.

**`policy.min_length` is not enforced on this endpoint**, and `verdict` is never
`too_short`. A digest doesn't carry the length of the password it came from:
the SHA-1 of `"a"` is forty hex characters, same as the SHA-1 of a forty-character
passphrase. If you need a minimum length, check it before you hash. This is the
same limitation `/api/v1/check/batch` has, for the same reason.

The same goes for `weak`: strength scoring needs the plaintext password to run
the zxcvbn-ts worker against, and this endpoint never has one, only a digest.
`verdict` is never `weak` here either.

### GET /api/v1/config

Returns the strength settings and message strings the page uses, so no copy is
hardcoded in the JavaScript: a `strength` object carrying `enabled`,
`min_score` and `policy.min_length` (as `min_length`), and a `messages` object
with one string per verdict plus `degraded` and `error`. Deliberately narrow:
nothing about proxies, timeouts, or which backends are wired up, and not
`strength.timeout`, which is server-side only.

### GET /docs

An in-browser console, rendered by Swagger UI from the OpenAPI document at
`GET /api/v1/openapi.json`. Every endpoint on this page can be fired against
the running server directly from the browser.

The document is OpenAPI 3.1 and lives in `openapi.yaml` at the repository root.
It is hand-written and parsed once at startup, so a malformed document stops
the process rather than surfacing as a 500 later. A test compares it against
Flask's URL map in both directions, so an endpoint added without a spec entry,
or documented without existing, fails the suite. Three routes are exempt by
name, because they serve the documentation rather than appearing in it: `GET /`,
`GET /docs`, and `GET /api/v1/openapi.json`. The exemption is keyed on the
endpoint, not the path, so a future `POST /` would still need a spec entry.

To generate a client:

```bash
curl -s http://127.0.0.1:8080/api/v1/openapi.json > amiweak.json
openapi-generator-cli generate -i amiweak.json -g python -o ./client
```

Both `/docs` and `/api/v1/openapi.json` are gated on `docs.enabled`, which
defaults to `true`. When it is false, both return 404.

**A word of caution.** The console sends whatever you type to the real backend,
and `POST /api/v1/check` takes a plaintext password. Requests from the console
count against the same rate limits as any other client. Use throwaway values.

Two things the page deliberately does not do. It loads Swagger UI's plain
bundle rather than the standalone preset, because the preset's top bar carries
a spec-URL field, which would let a visitor repoint try-it-out at a host of
their choosing and send passwords there. And `persistAuthorization` is off, so
nothing is written to browser storage; note that setting governs the Authorize
dialog's credentials only, and never had any bearing on request bodies.
On a deployment where a password-accepting console on a reachable URL is not
wanted, set:

```yaml
docs:
  enabled: false
```

or `AMIWEAK_DOCS__ENABLED=false` in that environment.

## Monitoring

### GET /healthz

```json
{
  "status": "ok",
  "version": "1.0.0",
  "uptime_seconds": 5821.4,
  "checks": {
    "hibp": {"enabled": true, "last_ok": "2026-07-31T09:12:03Z", "last_error": null},
    "weakpass": {"enabled": true, "last_ok": "2026-07-31T09:12:03Z", "last_error": null},
    "denylist": {"enabled": true, "last_ok": "2026-07-31T09:12:03Z", "last_error": null},
    "zxcvbn": {"enabled": true, "last_ok": "2026-07-31T09:12:03Z", "last_error": null}
  }
}
```

`status` is `degraded` when an enabled backend's most recent outcome was an
error. This reports what real traffic already observed rather than probing the
upstreams itself, because a health endpoint that made outbound calls would turn
your monitoring system into an amplifier pointed at HIBP.

### GET /metrics

JSON counters: `checks_total`, `verdicts_total` by verdict,
`backend_requests_total` and `backend_errors_total` by backend, plus
`backend_latency_seconds` per backend: `count`, `sum`, and `max`, not a
histogram; there is no quantile estimate to compute from that. No label
anywhere derives from a password or a hash. The only strings that become keys
are the fixed verdict names and the fixed backend names.

Also present:

- `cache_hits_total` / `cache_misses_total`: prefix cache lookups, by backend. Only backends that opt into the cache appear: the denylist sets `cacheable = False` (its lookup is an in-memory dict, and caching it would evict genuinely expensive HIBP and weakpass ranges from the LRU), so it is absent from both, and it costs nothing against `batch.rate_limit` either.
- `batch_requests_total`: number of `POST /api/v1/check/batch` requests served.
- `batch_items_total`: total items across every batch request, regardless of verdict.
- `backend_algorithm_total`: successful fetches per backend, by algorithm (`sha1`/`ntlm`).
- `store_errors_total`: state store operations that fell back to per-process state; see [Sharing state across workers](#sharing-state-across-workers) for what that means.

**`checks_total` and `verdicts_total` count items, not requests.** Both the
interactive `/api/v1/check` route and the batch route resolve a verdict per
item, and each resolution increments these counters once, so a single
1000-item batch moves them by 1000, not by 1. If you have a dashboard built on
`checks_total` from before batch checking existed, expect it to jump by orders
of magnitude the first time someone runs a batch; that is the counter working
as intended, not a regression.

**`backend_requests_total` counts prefix fetches, not checks.** A cache hit
resolves a prefix without touching the backend at all, so it does not
increment this counter. On a single check, which used to fetch a prefix on
every call, this counter tracked `checks_total` closely; with the shared
prefix cache now in the interactive path too, expect it to sit below
`checks_total` whenever the cache is warm.

By default counters are per worker process. With four gunicorn workers a
scrape sees one worker's view. Same story for the rate limiter, where the
effective allowance is roughly `requests × workers`. It exists to stop casual
hammering, not a determined attacker. Set `state.path` (see
[Sharing state across workers](#sharing-state-across-workers)) to put both the
counters and the rate-limit buckets in one SQLite file every worker shares;
then a scrape sees the whole deployment's counters, and `requests` means what
it says regardless of worker count.

**Cache memory is per worker, too.** 256 entries is roughly 40-60 MB; with four
gunicorn workers that's four separate caches, not one shared 40-60 MB pool.
Raise `cache.max_entries` deliberately, with the worker count in mind.

**`batch.deadline` and `batch.max_items` move together.** A full, uncached batch
needs up to `max_items × 2` prefix fetches (one per backend per distinct
prefix), run `max_concurrency` at a time. Raising `max_items` without raising
`deadline` to match just makes full batches start timing out.

**The batch rate limit is a separate bucket from `policy.rate_limit`.** It has
to be: one full batch can cost thousands of prefixes, and metering it against
the interactive allowance would exhaust that allowance in a single request.
`batch.rate_limit` counts distinct uncached prefixes instead of requests, so an
audit you re-run inside `cache.ttl_seconds` costs nothing.

### GET /metrics/prometheus

The same counters as `/metrics`, rendered in Prometheus text exposition format
instead of JSON. `/metrics` is unchanged and keeps serving JSON; this is a
second view of one snapshot, not a replacement, so the two can never disagree.

```yaml
scrape_configs:
  - job_name: amiweak
    metrics_path: /metrics/prometheus
    static_configs:
      - targets: ["localhost:8080"]
```

Every series is prefixed `amiweak_`. One has no `/metrics` counterpart at all:
`amiweak_build_info`, always 1, with the running version in a `version` label.
`amiweak_uptime_seconds` mirrors the JSON field of the same name and carries
the same per-worker caveat. A family with no
observations still emits its `# HELP`/`# TYPE` header, so a metric that has
not fired yet reads as empty rather than as a broken exporter.

`amiweak_backend_healthy` is the alertable form of the `degraded` status
`/healthz` reports: 1 when a backend's most recent outcome was not an error,
0 otherwise, per backend.

Latency (`amiweak_backend_latency_seconds_count` / `_sum`, plus a separate
`amiweak_backend_latency_seconds_max` gauge) is a summary without quantiles:
the underlying data is only count, sum, and max, so there is no `quantile="…"`
series and no real percentile estimate to compute one from.

**Read [Sharing state across workers](#sharing-state-across-workers) before
building alerts on this endpoint.** With the default `state.path: null` and
the four workers `gunicorn.conf.py` defaults to, a scrape of
`/metrics/prometheus` sees
whichever one worker answered it, not the deployment's total: exactly the
same per-worker caveat that already applies to `/metrics`.

## Adding a backend

One file and two registrations.

```python
# amiweak/checks/mysource.py
class MySourceChecker(RangeChecker):
    name = "mysource"
    cacheable = True  # False opts a backend out of the prefix cache entirely,
                       # e.g. an in-memory lookup with nothing worth caching.

    def __init__(self, session, config):
        self._session = session
        self._config = config

    def supports(self, algorithm: Algorithm) -> bool:
        return algorithm in (Algorithm.SHA1, Algorithm.NTLM)

    def prefix_of(self, digest: str, algorithm: Algorithm) -> str:
        return digest[:5]

    def fetch(self, prefix: str, algorithm: Algorithm) -> RangeFetch:
        # One network call per prefix. Return a RangeFetch either way: errors
        # are returned, not raised, so the caller can tell a result worth
        # caching from one that must not be.
        ...

    def lookup(self, data: RangeData, digest: str) -> CheckResult:
        # Pure, no I/O: resolve one digest against an already-fetched range.
        ...
```

`RangeChecker` supplies `check()` from those four primitives, splitting a range
lookup into its two halves: one network fetch per *prefix*, and a pure lookup
per *digest*. `fetch` is the one that matters most, because it is the only
method everything else in the system attaches to: the prefix cache, metrics,
the batch rate limiter, and the concurrency cap on a batch all wrap calls to
`fetch`. A backend that reaches out to the network from anywhere else (inside
`lookup`, say, or from its own background thread) silently opts out of all of
that: no caching, no metering, no limit.

Then add it to `_build_runner` in `amiweak/app.py`, give it a `checks.mysource`
block (including `algorithms`) in both `DEFAULTS` in `amiweak/config.py` and
`config.yaml`, and add an entry to `VERDICT_BY_CHECK` in
`amiweak/checks/runner.py`. That tuple decides which verdict a hit produces and
in what order verdicts win, and without an entry there your hits never surface.

Send only a hash prefix, and keep `CheckResult.error` inside the existing closed
vocabulary (`timeout`, `network`, `internal`, `http_<status>`). Upstream
exception text can embed the request URL, and the URL embeds the prefix.

## Development

```bash
pytest                              # requires Node.js on PATH (strength scoring)
pytest tests/test_no_leak.py -v     # the leakage guarantees
ruff check . && ruff format .
mypy
semgrep scan --config p/security-audit --config p/secrets \
  --config p/python --config p/flask --config p/owasp-top-ten --metrics=off .
```

`semgrep` lives in its own `security` extra, not `dev` — install with
`.[dev,security]` to get it (see [Install](#install)).

`tests/checks/test_real_payloads.py` parses verbatim slices of live HIBP and
weakpass responses, kept in `tests/fixtures/`. The hand-written parser tests only
prove the parser matches my assumptions about the wire format. Those fixtures
prove the assumptions. If a provider changes format, they fail before production
starts quietly answering "safe".

### A note on the parser

An earlier prototype binary-searched the range response body, which assumes the
provider returns rows sorted by hash. Neither API documents that ordering, and
getting it wrong yields a false "safe", which is the worst failure this tool can
produce. A range is about 2000 rows, so it now parses into a dict once and looks
up in constant time. That also gets the HIBP occurrence count for free, which is
what the page shows when it tells you a password has been seen 52 million times.

## Layout

```
config.yaml                  every setting, with the defaults and their reasoning
openapi.yaml                 the API specification, served at /api/v1/openapi.json
wsgi.py                      the gunicorn entry point (`wsgi:app`)
run.py                       the development server
gunicorn.conf.py             production server settings, access log format included
denylist.txt.example         template for the organisational denylist
amiweak/
  config.py           YAML + env overrides + validation
  algorithms.py       Algorithm enum (sha1, ntlm) and digest validation
  hashing.py          sha1_hex
  http.py             requests.Session (proxy, TLS, retries)
  logging_setup.py    redaction, unavoidably
  metrics.py          counters for /metrics and /healthz
  prometheus.py       renders Metrics.snapshot() as Prometheus text exposition
  store.py            StateStore: MemoryStore (per worker) or SqliteStore (state.path)
  cache.py            PrefixCache, an LRU of parsed ranges by (backend, algorithm, prefix)
  rate_limit.py       per-process token bucket
  strength.py          StrengthScorer: a persistent Node worker running zxcvbn-ts
  strength_worker.js    the Node worker script itself
  denylist.py          Denylist: loads the word file, expands rules, fingerprints and
                        caches the digest set
  digest_store.py      binary reader/writer for the persistent digest cache file
  openapi.py           parses openapi.yaml, once, at startup
  app.py              application factory
  checks/             base.py, hibp.py, weakpass.py, denylist.py, runner.py
  routes/             web.py, api.py, ops.py, docs.py (/docs and /api/v1/openapi.json)
static/              css, js, vendored zxcvbn-ts and Swagger UI (no CDN)
templates/           index.html, docs.html (the Swagger UI console)
rules/               hashcat-format rule files for denylist expansion (corporate.rule)
```

zxcvbn-ts and Swagger UI are both committed under `static/vendor/` instead of
loaded from a CDN. No build step, no npm at deploy time, and the
Content-Security-Policy gets to stay `default-src 'self'`, which it could not
if either came off a third-party host. A page that receives passwords should
not be asking a stranger for its JavaScript.

The design document and implementation plan live in `docs/superpowers/`.
