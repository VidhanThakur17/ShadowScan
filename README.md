# ShadowScan: HTTP Asset Monitoring & Delta Intelligence

> **Authorized use only.** Run ShadowScan only against systems you own or are explicitly
> authorized to test, such as targets listed in scope for a bug bounty program you take part in.
> This module does lightweight, passive monitoring: one GET per target (plus in-scope redirects),
> with bounded concurrency. It does no brute forcing, crawling, or exploitation.

ShadowScan probes thousands of in-scope hosts concurrently and fingerprints each response. It
stores every observation in SQLite and reports what changed since the last run. It also judges
**which changes are worth a human's attention**: it suppresses dynamic-token noise, measures how
much content changed, flags notable HTTP transitions, and ranks every change by `review_priority`.

## Architecture

```
domains.txt ─► utils.parse_targets ─► Scanner
             (normalize, host identity,  │
              merge scheme intent)       ├─ producer: Semaphore(concurrency) → probe tasks
                                         │     └─ HttpProber (one shared aiohttp ClientSession)
                                         │          manual redirects + scope check per hop
                                         │          ephemeral per-probe cookie jar
                                         │          body streamed → FingerprintEngine (≤ MAX_RESPONSE_BYTES)
                                         │              raw_sha256 + normalized_sha256 + similarity sketch
                                         │              (large bodies finalized in a worker thread)
                                         │
                                         ├─ bounded asyncio.Queue (backpressure)
                                         │
                                         └─ writer task → batches → one DB thread → SQLite (WAL)
                                                 per batch, in ONE transaction, per result:
                                                 asset (by key) → previous + baseline obs (PK lookups)
                                                 → compare_content (similarity only if changed)
                                                 → detect_changes → scoring.assess
                                                 → insert observation/fingerprints/changes
                                                 → update asset pointers + history counters
                                                                           │
                                                    deltas.json (this run, sorted by review_priority)
                                                    + console summary (top changes)
```

| Module | Responsibility |
|---|---|
| `config.py` | Defaults (`MAX_CONCURRENCY`, similarity thresholds, …) and the `ScanConfig` dataclass |
| `models.py` | `Target`, `ProbeResult`, `Change`, `AssetHistory`, `ErrorType`, `ChangeType`, `RunSummary` |
| `utils.py` | Target normalization, host-based identity, de-duplication, redirect `ScopePolicy`, logging |
| `http_probe.py` | Async probing, redirects, per-probe cookies, bounded body reads, error classification |
| `fingerprint.py` | Pluggable fingerprinters: raw SHA-256, normalized SHA-256 plus similarity sketch, titles |
| `normalization.py` | Conservative, rule-by-rule noise normalization |
| `similarity.py` | Bounded content sketches and similarity |
| `delta.py` | Change detection, content comparison, `deltas.json` |
| `scoring.py` | `interesting` / `reason` / `review_priority` rules (all weights in one table) |
| `database.py` | SQLite schema v2, WAL, batched transactions |
| `scanner.py` | Producer/consumer orchestration and graceful shutdown |
| `main.py` | CLI and console summary |

## Installation

Requires Python 3.12+.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python -m shadow_scan.main --input domains.txt

python -m shadow_scan.main --input domains.txt --concurrency 150 --timeout 10 \
    --database shadowscan.db --output deltas.json
```

| Option | Default | Meaning |
|---|---|---|
| `--input, -i` | `domains.txt` | Targets file |
| `--database, -d` | `shadowscan.db` | SQLite database |
| `--output, -o` | `deltas.json` | Delta report for this run |
| `--concurrency, -c` | 100 | Max in-flight targets (also the connection pool size) |
| `--timeout, -t` | 10 | Connect (incl. DNS) and per-read timeout, seconds |
| `--total-timeout` | max(3×timeout, 30) | Hard ceiling per HTTP request |
| `--max-bytes` | 5 MiB | Max body bytes read per response |
| `--max-redirects` | 5 | Max in-scope redirect hops |
| `--no-http-fallback` | off | Don't retry scheme-less targets over HTTP |
| `--allow-subdomain-redirects` | off | Also follow redirects to subdomains of supplied hosts |
| `--insecure` | off | Skip TLS certificate verification |
| `-H 'Name: value'` | — | Extra header (repeatable), e.g. a program's researcher ID header |
| `--user-agent` | `ShadowScan/0.1 …` | User-Agent |
| `--verbose, -v` | off | Debug logging; prints every change live and lists all of them in the summary |

Exit codes: `0` completed, `1` failed, `130` interrupted (Ctrl+C saves everything already
collected, marks the run `interrupted` and still writes `deltas.json`).

### Console summary

```
ShadowScan completed

Targets:                 5,284
Reachable:               4,103
Unreachable:             1,181
Incomplete:                 12
Changes:                    42
Interesting:                 9
Noise suppressed:           57

Top changes:

[ 95]* admin.example.com     403 -> 200
[ 80]* api-v2.example.com    newly reachable (HTTP 200)
[ 60]  portal.example.com    major content change (similarity 0.23)
[ 25]  www.example.com       title 'Home' -> 'Welcome'
```

Only the top `TOP_CHANGES_SHOWN` changes are listed. Live `[CHANGE]` log lines appear only for
interesting changes or those with priority ≥ `CONSOLE_PRIORITY_THRESHOLD`. `--verbose` shows
everything.

## Asset identity

An asset is identified by **`host[:port][/path]` without a scheme**, so `example.com` and
`https://example.com` are the same asset and share one history. User intent is stored separately:

| Stored | Where |
|---|---|
| hostname, explicit non-default port, path | `assets.hostname`, `assets.port`, `assets.path` |
| original input line | `assets.original_input` |
| requested scheme (`http`/`https`, or `NULL` = auto) | `assets.requested_scheme` |
| scheme that actually answered | `observations.scheme` |
| whether the HTTPS→HTTP fallback was used | `observations.fallback_used` |
| final URL after in-scope redirects | `observations.final_url` |

Rules:
- An explicit scheme is always respected. `https://example.com` never falls back to HTTP.
- A scheme-less target tries HTTPS first and falls back to HTTP only on a transport-level failure
  (connection refused, connect timeout, connection error, TLS error).
- When the input lists the same asset with and without a scheme, the **explicit scheme wins**.
  Two different explicit schemes keep the first one and log a warning.
- Editing `domains.txt` to change the scheme updates the asset's intent and keeps its history.

## Observation completeness

Each observation records two independent facts:

| | `http_reachable` | `observation_complete` |
|---|---|---|
| HTTP 200, body fully read | true | true |
| HTTP 200, body > `MAX_RESPONSE_BYTES` (`response_too_large`) | true | false |
| Redirect loop / limit exceeded | true | false |
| Body read failed after headers | true | false |
| DNS failure / refused / TLS error / timeout | false | false |

Availability changes use `http_reachable`. Content and title comparisons use **only complete
observations**: the current probe is compared against the asset's most recent *complete*
observation (its content baseline). A truncated or failed read is therefore never reported as a
content change.

## Fingerprints: raw vs normalized

Every complete observation stores two fingerprints, in `observations` and in
`observation_fingerprints`:

- **`raw_sha256`** (`observations.body_sha256`): SHA-256 of the exact body bytes. It is never removed.
- **`normalized_sha256`**: SHA-256 of a text body after conservative noise normalization.

The normalizer (`normalization.py`) is an ordered list of small rules, each tested on its own:

| Rule | What it neutralizes |
|---|---|
| `strip_html_comments` | `<!-- … -->` (render timestamps, cache IDs) |
| `mask_csrf_tokens` | values of `<meta>`/`<input>` fields with exact token names (`csrf-token`, `authenticity_token`, `__VIEWSTATE`, …) |
| `mask_nonces` | `nonce` / `data-nonce` attribute values inside tags |
| `mask_request_ids` | opaque values in `data-request-id`-style attributes, `<meta name="trace-id">`, JSON `"requestId"`-style keys |
| `mask_render_timestamps` | epoch/ISO values in `data-timestamp`-style attributes, `<meta name="generated-at">`, JSON `"serverTime"`-style keys |
| `collapse_whitespace` | indentation and line-ending differences |

These are **deliberately never normalized**: script/style `src`, links, form actions, cache-busting
query strings (`app.js?v=…`), build/version/modified timestamps, hidden inputs with non-token names,
and visible text. A change there may mean a new deployment or a new endpoint.

**Binary responses** (images, PDFs, archives, or bodies containing NUL bytes): `normalized_sha256`
equals `raw_sha256` (normalization is the identity), and there is no similarity sketch. **Text
over `NORMALIZATION_MAX_BYTES`** gets no normalized hash, and comparisons fall back to raw-vs-raw.
A normalized hash is never compared with a raw one.

If the raw hash changed but the normalized hash did not, no delta is emitted. The run counts it as
"noise suppressed" (`raw_only_changes_suppressed` in `deltas.json`).

## Similarity

`content_similarity` (0.0 to 1.0) measures how much the normalized text changed. 1.0 means
effectively identical and 0.0 means nothing in common. It is computed only when the normalized hash
changed, and only against the immediately previous complete observation.

How it works: normalized text is tokenized into tags and words. Tokens are grouped into
content-defined chunks, so an insertion doesn't shift every later chunk. Each chunk is hashed to 32
bits, and the asset keeps **one** compact sketch of its current baseline in
`asset_content_baselines` (about 4 bytes per 8 tokens). Similarity is
`difflib.SequenceMatcher.quick_ratio()` over the two chunk sequences: a linear-time match ratio. It
measures *how much* changed, not *where*. Texts larger than `SIMILARITY_MAX_BYTES` are not sketched,
and their similarity is reported as not measured instead of estimated from a prefix.

## Delta classifications

| Type | When | Notes |
|---|---|---|
| `new_asset` | first observation of an asset | only event for that asset in the run |
| `availability_changed` | `http_reachable` flipped | only event; old/new state attached |
| `error_changed` | still unreachable, failure mode changed (e.g. `dns_failure → connection_refused`) | |
| `status_changed` | status code changed | title/server/redirect/content differences are attached as `context`, not emitted separately |
| `redirect_changed` | final `Location` changed | `host_changed` flag; a 3xx body change is folded into it |
| `title_changed` | `<title>` changed vs the content baseline | complete observations only |
| `server_header_changed` | `Server` header changed | |
| `content_changed_minor` | normalized content changed, similarity ≥ `SIMILARITY_MAJOR_THRESHOLD` (0.80) | `magnitude`: `trivial` (≥ 0.98) or `minor` |
| `content_changed_major` | similarity < 0.80, or not measurable (binary or very large text) | `magnitude`: `major` or `unmeasured` |

## Interesting & review priority

**`interesting` does NOT mean "vulnerable".** It means the state transition may deserve human
review. `review_priority` (0–100) ranks how worthwhile a change is to look at first. It is
deliberately *not* a severity, risk score or CVSS. All rules and weights are in `scoring.py`
(`PRIORITY`).

| Transition | Priority | Interesting |
|---|---:|:---:|
| 403 → 2xx | 95 | ✓ |
| 401 → 2xx | 90 | ✓ |
| 404/410 → 2xx | 85 | ✓ |
| unreachable → reachable (2xx / other) | 80 / 65 | ✓ |
| 5xx → 2xx | 70 | ✓ |
| 3xx → 2xx (redirect → direct content) | 65 | ✓ |
| major content change | 60 | |
| 2xx → 401/403 | 55 | ✓ |
| new asset (reachable) | 50 | |
| `dns_failure` → other error (name now resolves) | 45 | ✓ |
| content changed, magnitude unmeasured | 40 | |
| 2xx → 5xx · redirect to a different host | 40 | |
| reachable → unreachable · other status change | 35 | |
| redirect destination changed | 30 | |
| title changed · 2xx → 404/410 | 25 | |
| other error → `dns_failure` | 20 | |
| minor content change · new unreachable asset · other error change | 15 | |
| server header changed | 10 | |
| trivial content change (similarity ≥ 0.98) | 5 | |

## Historical change ratio

Each asset keeps running counters, updated in O(1) per observation and never computed by scanning
history: `observations_count`, `content_comparisons` (pairs of complete observations compared),
`content_change_count` (normalized content differed) and `last_content_change_at`.
`change_ratio = content_change_count / content_comparisons` is included in every content delta's
`history`. A page at 47/50 is probably naturally dynamic. Nothing is suppressed automatically yet;
the metric is exposed for a later prioritization stage.

## Example `deltas.json`

```json
{
  "run_id": 3,
  "run_timestamp": "2026-10-08T07:19:59.302Z",
  "finished_at": "2026-10-08T07:19:59.327Z",
  "status": "completed",
  "duration_seconds": 0.04,
  "targets_total": 5,
  "targets_processed": 5,
  "reachable": 5,
  "unreachable": 0,
  "incomplete_observations": 0,
  "errors_by_type": {},
  "changes_found": 3,
  "interesting_changes": 2,
  "raw_only_changes_suppressed": 1,
  "changes_by_type": { "availability_changed": 1, "content_changed_major": 1, "status_changed": 1 },
  "changes": [
    {
      "target": "admin.example.com",
      "type": "status_changed",
      "old_status": 404,
      "new_status": 200,
      "context": { "title": { "old": null, "new": "Admin console" },
                   "content": { "similarity": 0.0, "magnitude": "major" } },
      "interesting": true,
      "reason": "Previously missing endpoint (404) now returns HTTP 200",
      "review_priority": 85
    },
    {
      "target": "api-v2.example.com",
      "type": "availability_changed",
      "old": { "state": "unreachable", "status_code": null, "error_type": "connection_timeout" },
      "new": { "state": "reachable", "status_code": 200, "error_type": null, "title": "Home" },
      "previous_checked_at": "2026-10-08T07:19:53.417Z",
      "interesting": true,
      "reason": "Previously unreachable host now responds (HTTP 200)",
      "review_priority": 80
    },
    {
      "target": "portal.example.com",
      "type": "content_changed_major",
      "similarity": 0.2285,
      "magnitude": "major",
      "old_normalized_hash": "7a59…", "new_normalized_hash": "482f…",
      "old_raw_hash": "7cd4…", "new_raw_hash": "ee47…",
      "baseline_checked_at": "2026-10-08T07:19:53.417Z",
      "history": { "observations": 3, "content_comparisons": 2, "content_changes": 1, "change_ratio": 0.5 },
      "interesting": false,
      "reason": "Major content change",
      "review_priority": 60
    }
  ]
}
```

Changes are sorted by `review_priority` (highest first), then target, then type.

## Database structure (schema v2)

| Table | Purpose |
|---|---|
| `runs` | One row per run: status and counters (incl. `interesting_changes`, `raw_only_changes`, `incomplete`) |
| `assets` | Host-based identity, intent (`requested_scheme`, `original_input`), pointers `last_observation_id` / `last_complete_observation_id`, history counters |
| `observations` | Every probe: URLs, actual scheme, `fallback_used`, `http_reachable`, `observation_complete`, status, headers, sizes, `body_sha256` (raw), `normalized_sha256`, `content_similarity` + `content_baseline_observation_id`, title, redirect, timing, error |
| `observation_fingerprints` | `(observation_id, name, value)`: `raw_sha256`, `normalized_sha256`, future strategies |
| `asset_content_baselines` | One similarity sketch per asset (current baseline only; overwritten, so storage stays bounded) |
| `changes` | Every delta with `interesting`, `review_priority`, `reason`, details JSON, links to current/previous observation |

The database runs in WAL mode, with `synchronous=NORMAL` and foreign keys on. Change detection does
primary-key lookups only, via the asset pointers. When content is unchanged, only the baseline
pointer moves and the sketch blob isn't rewritten.

**Migration policy:** `PRAGMA user_version` tracks the schema, and new databases are created at v2.
Phase 1 (v1) databases are **refused with instructions** and are not migrated, because the
identity change would require merging asset histories. Point `--database` at a new file and keep
the old one for reference.

```sql
-- This run's interesting changes, highest priority first
SELECT a.target, c.change_type, c.review_priority, c.reason
FROM changes c JOIN assets a ON a.id = c.asset_id
WHERE c.run_id = (SELECT MAX(id) FROM runs) AND c.interesting = 1
ORDER BY c.review_priority DESC;

-- Naturally dynamic pages
SELECT target, content_change_count, content_comparisons,
       ROUND(1.0 * content_change_count / content_comparisons, 2) AS change_ratio
FROM assets WHERE content_comparisons >= 5 ORDER BY change_ratio DESC;
```

## Performance configuration

Defaults live at the top of `shadow_scan/config.py`:

```python
MAX_CONCURRENCY = 100
REQUEST_TIMEOUT = 10
TOTAL_REQUEST_TIMEOUT = 30
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_REDIRECTS = 5
DB_BATCH_SIZE = 200
DB_FLUSH_INTERVAL = 2.0
NORMALIZATION_MAX_BYTES = 1024 * 1024    # text above this: raw hash only
SIMILARITY_MAX_BYTES = 512 * 1024        # normalized text above this: similarity not measured
SIMILARITY_CHUNK_DIVISOR = 8
CPU_OFFLOAD_BYTES = 64 * 1024            # larger bodies are normalized in a worker thread
SIMILARITY_TRIVIAL_THRESHOLD = 0.98
SIMILARITY_MAJOR_THRESHOLD = 0.80
CONSOLE_PRIORITY_THRESHOLD = 40
TOP_CHANGES_SHOWN = 10
```

- Memory per in-flight probe: ≤ 256 KB title head + ≤ `NORMALIZATION_MAX_BYTES` text buffer
  (binary is never buffered). The queue holds at most `2 × concurrency` results, each with a
  sketch of ≤ ~256 KB (typically a few KB).
- CPU-heavy work stays off the event loop. Normalization of bodies > 64 KB runs in a worker thread.
  Similarity runs in the DB thread, only when content changed, in linear time over a bounded
  sketch.
- Still one SQLite writer.

## Tests

```bash
python -m pytest -q          # or: python -m unittest discover -s tests
```

82 offline tests use a local aiohttp server on `127.0.0.1`. They cover target identity, explicit
HTTPS and fallback, per-probe cookies and cookie isolation, completeness, every normalization rule
(including what must *not* be normalized), similarity, all delta classifications and transitions,
priority ordering, binary responses, off-scope redirects, a v1-database refusal, and multi-run
controlled-change scenarios.

## Known limitations

- **Normalization is conservative on purpose.** Tokens with unusual names, volatile values in free
  text ("rendered in 12 ms"), rotating ads/recommendations and A/B variants still produce content
  changes. Use `change_ratio` to spot such pages. Stripping HTML comments means a changed comment
  only shows as "noise suppressed", even though the raw hash records it.
- **Similarity ignores order** (multiset of chunks). Pure reordering scores as near-identical.
  Similarity is not measured for binary bodies or text over `SIMILARITY_MAX_BYTES`, and those
  changes are reported as `content_changed_major` with `magnitude: "unmeasured"`.
- Sketches are stored only for the current baseline. Similarity against older history isn't possible.
- Truncated bodies (`response_too_large`) are recorded but never content-compared.
- Cookies are kept only within one redirect chain. There is no login or session automation.
- Phase 1 databases are not migrated (see migration policy).
- `review_priority` and `interesting` are deterministic heuristics, not vulnerability findings.
- Scope is host-based. Ports and paths aren't restricted for redirects.

---

# Recon & Attack-Surface Mapping

The recon subsystem (`shadow_scan/recon/`) turns ShadowScan from a change monitor into a
persistent attack-surface intelligence system. It is layered on top of the monitoring engine and
**reuses** its HTTP probing, fingerprints, scoring and single-writer SQLite design. Everything is
bounded and intended for **authorized** bug-bounty recon: passive discovery, DNS, bounded
service/URL discovery, safe crawling, static JavaScript analysis and deterministic correlation.
There is **no** exploitation, brute force, credential attack, fuzzing, payload injection, DoS
behaviour or GraphQL introspection.

## Pipeline

```
discovery -> dns -> http -> services -> urls -> crawl -> javascript -> enrichment -> correlation
```

Each stage's status (`pending/running/completed/failed/skipped`) is stored in `recon_stages`, so a
failed or interrupted run resumes with `--resume` and only re-runs incomplete stages. Scope is
enforced before every active request.

| Stage | What it does | Reuses / tools |
|---|---|---|
| discovery | seeds + passive subdomain tools, dedup, scope-classify, record source | subfinder/amass/findomain (optional) |
| dns | async bounded resolution, A/AAAA/CNAME, transition events | stdlib getaddrinfo |
| http | monitors resolved in-scope hosts | the monitoring `Scanner`, unchanged |
| services | bounded port profiles, new/closed/changed ports | naabu/nmap (optional) |
| urls | passive URL inventory, normalize + dedup + scope-classify | gau/waybackurls (optional) |
| crawl | bounded, scope-safe GET crawl; links, JS URLs, tech, favicon, GraphQL | `HttpProber.fetch` |
| javascript | fetch + analyze JS, source maps, findings | `HttpProber.fetch` |
| enrichment | conventional OpenAPI specs, favicons | `HttpProber.fetch` |
| correlation | combine signals into review items, noise-aware ranking | — |

## Scope engine

A first-class `ScopeEngine` classifies every discovered object as `IN_SCOPE`, `OUT_OF_SCOPE` or
`UNKNOWN`, and **nothing out of scope is ever requested** (UNKNOWN only with `--probe-unknown`).
Scope file syntax:

```
example.com                 # exact host
*.example.com               # wildcard root (subdomains, not the apex)
https://portal.example.com  # explicit URL -> host + scheme + port constraint
!admin.example.com          # excluded host
!~\.internal\.example\.com$ # excluded regex (prefix !~)
@ports 80,443,8443          # allowed ports
@scheme https               # allowed schemes
```

## Tool adapters

External binaries sit behind adapters in `shadow_scan/recon/tools/`. Each adapter detects
availability, builds a **subprocess argument array** (never a shell string, so target names cannot
inject commands), runs with a timeout, and parses output. Missing or timed-out tools degrade
gracefully (empty result, warning) and never abort a run. All adapters are optional.

## Intelligence stored

- **DNS** (`dns_records`): status, A/AAAA, CNAME, `changed_at`; events `new_subdomain`,
  `dns_became_live/dead`, `cname_changed`, `ip_changed`, and a `dangling_cname` **review signal**
  (never a takeover claim).
- **Services** (`services`): host/port/proto/guess/banner/source; `new_open_port`, `closed_port`,
  `service_changed`. New web ports score higher.
- **URLs** (`urls`): normalized, deduped, scope-classified, with query parameter names. Historical
  URLs are kept even when no longer live. Off-scope URLs are stored but never fetched.
- **JavaScript** (`javascript_assets`, `js_findings`): raw SHA-256, size, source-map ref, and
  layered findings — endpoints, routes, hostnames, params, config refs, **conservative** secret
  candidates (shape + context based, with a false-secret filter), source maps. Events include
  `js_changed`, `new_js_endpoint`, `new_secret_candidate`, `new_source_map`.
- **Endpoints** (`endpoints`): identity `(host, METHOD, normalized_path)` with `{id}`/`{uuid}`
  placeholders, so HTML/JS/history/OpenAPI collapse to one row. Method is `KNOWN`/`INFERRED`/
  `UNKNOWN` and never assumed `GET`.
- **Parameters** (`parameters`): name + location (`query/path/body/header/cookie/unknown`) +
  endpoint + source. Sensitive names (`admin`, `role`, `redirect`, `token`, ...) raise review
  priority — never a vulnerability claim.
- **OpenAPI**: valid specs at conventional paths are parsed into endpoints/params/auth schemes;
  a new spec is an interesting recon event. **GraphQL** endpoints are recorded as *candidates*
  only (no introspection).
- **Technologies** (`technologies`) and **favicons** (`favicons`): passive evidence only;
  `technology_added/removed`, `version_changed`, `favicon_changed`.

## Correlation, ranking and the review queue

The correlation engine (`correlation.py`) combines an asset's signals into explainable
`recon_signals` with a stable `rule_id`, reason and `review_priority` (0-100). Rules and weights
are centralized. Examples: new live host + OpenAPI (96), revived host + new port (92), changed JS
introducing an internal endpoint (91), new OpenAPI with many endpoints (90), new web port (80),
new admin-ish subdomain (78). An interesting monitoring HTTP transition (e.g. 403->200) is carried
through at its monitoring priority.

**Noise-aware ranking:** on assets that change almost every run (high monitoring `change_ratio`),
*generic content-change* signals are down-ranked — but structural attack-surface signals (new
subdomain/port/endpoint/JS route/API doc) keep full weight.

The `review_items` queue reflects each asset's **current** standing (priority, reason, underlying
signals, `first_seen`, `latest_seen`, `status` in `new/reviewing/interesting/dismissed/resolved`).
**"interesting" means the state transition may deserve human review — not that anything is
vulnerable.**

## Recon CLI

```bash
shadow_scan recon   --input scope.txt [--database shadowscan.db] [--resume]
                    [--ports fast|web_extended|custom] [--max-depth N] [--max-urls N]
                    [--no-external-tools] [--no-services] [--no-urls] [--no-crawl] [--no-javascript]
shadow_scan review  --database shadowscan.db [--status new ...] [--set ASSET STATUS] [--summary]
shadow_scan stats   --database shadowscan.db
shadow_scan monitor --input domains.txt ...     # the HTTP monitor (also the bare, legacy form)
```

A bare `python -m shadow_scan.main --input domains.txt ...` still runs the monitor, unchanged.

### Example review queue

```
Researcher review queue

[ 92] api-new.example.com
      - Previously dead host now resolves, exposes new port(s) [8443] and serves HTTP 200
      - New API documentation exposes 27 previously unseen endpoints
[ 91] portal.example.com
      - Changed JavaScript introduced internal-looking endpoint(s): /api/internal/export
      - New sensitive-looking parameter(s): account_id
      - New JavaScript source map reference discovered
[ 85] admin-dev.example.com
      - Monitoring flagged an HTTP transition: Previously missing endpoint (404) now returns HTTP 200
      - New web-facing port(s) exposed: [8443]
```

## Recon schema

Recon tables are added to the same database additively (tracked by `recon_meta`, leaving the
monitoring `user_version` untouched): `recon_runs`, `recon_stages`, `hosts`, `discovery_sources`,
`dns_records`, `services`, `urls`, `javascript_assets`, `js_findings`, `endpoints`, `parameters`,
`technologies`, `favicons`, `recon_signals`, `review_items`. The single-writer model is preserved:
all writes go through one connection on one thread; the HTTP stage's monitoring `Scanner` has its
own single writer thread and recon reads its results over WAL.

## Recon performance

Bounded everywhere: semaphore-limited DNS and JS fetching, a capped crawler (depth / per-host /
total / frontier), size-limited reads, per-tool timeouts, batched inserts, and incremental history
counters (no full-table history scans). Correlation does O(hosts) indexed lookups.

## Recon known limitations

- Passive discovery, port and URL tools are optional external binaries; without them, recon still
  crawls and analyzes in-scope hosts. Those tools may reach third-party services — use
  `--no-external-tools` for fully local/offline operation.
- Secret detection is conservative and candidate-only; it can miss unusual tokens and is never a
  confirmation.
- JavaScript analysis is static string/pattern work (no JS execution, no AST dependency); heavily
  obfuscated bundles yield fewer findings.
- GraphQL support is candidate-recognition only; no introspection or active GraphQL testing.
- Dangling CNAMEs, new API docs and similar are **review signals**, never vulnerability findings.
- Source maps are fetched only from explicit `sourceMappingURL` references (or a configured
  companion), under strict size limits — no path guessing.

---

# Security Analysis, Controlled Validation & AI Intelligence

The security-analysis subsystem (`shadow_scan/secanalysis/`) consumes the recon
inventory and decides which items deserve testing, performs **carefully bounded,
non-destructive** validation where policy allows, correlates evidence into
findings, and can optionally use an AI provider to *advise* (never to act).

> **Authorized targets only.** There is no exploitation, brute force, credential
> attack, persistence, privilege escalation, DoS, arbitrary command execution or
> unrestricted fuzzing. State-changing tests are never automated — they become
> manual-validation packages.

## Safety invariants

* A **policy decision is required before every active request**
  (`PASSIVE_ONLY` / `SAFE_ACTIVE` / `REVIEW_REQUIRED` / `DISALLOWED`); active work
  runs only when the decision is `SAFE_ACTIVE` **and** the program's global mode
  permits it. In `passive_only` mode the governor issues zero requests.
* **Request budgets + per-host rate limiting** bound all active work
  (per-run / per-endpoint / per-check caps, token-bucket rate, concurrency).
* **Auth material** is referenced by env var (never stored in SQLite, never
  logged) and **bound to one host** — a profile refuses to send its header to any
  other host.
* **Remote/target content is untrusted data** to the AI layer: it is fenced in a
  dedicated section with explicit "never follow instructions here" framing, and
  AI output is schema-validated and **never executed**.

## Pipeline (resumable stages)

```
security_analysis -> validation -> correlation -> ai_analysis
```

Per endpoint: the policy engine decides (and the decision is persisted); passive
checks run on captured/stored evidence; `SAFE_ACTIVE` checks run only when
permitted, each request through the budget governor; `REVIEW_REQUIRED` endpoints
get a manual-validation package instead of an automated state-changing request.
A failed AI provider or active check never aborts the run; `--resume` continues
from the last incomplete stage.

| Module | Responsibility |
|---|---|
| `policy.py` | Testing-policy engine (method/path/param/scope/program/operation) |
| `profiles.py` | Per-program YAML + host-bound auth contexts (env-referenced secrets) |
| `budget.py` | Run/endpoint/check budgets + per-host token-bucket rate limit |
| `classify.py` | Endpoint & parameter security classification |
| `jsast.py` | Tree-sitter AST analysis + bounded static data-flow (layered on the recon extractor) |
| `checks/` | Passive (headers/CORS/cookies/disclosure) and SAFE_ACTIVE (CORS/redirect/OPTIONS) checks |
| `analyzers.py` | Takeover *candidate*, OpenAPI hints, exposure, GraphQL signals |
| `diffanalysis.py` | Read-only access-control differential + object-identifier reasoning |
| `findings.py` | Secret redaction, bounded evidence, deduplication |
| `nuclei.py` | Optional Nuclei adapter — safe profiles only, defensive result filtering |
| `ai.py` | Provider abstraction, untrusted-isolation prompts, schema validation, caching |
| `seccorrelation.py` | Explainable, bounded correlation into review items |
| `manualpkg.py` | Reproducible manual-validation packages (Burp-friendly) |
| `sec_db.py` | Security schema v4 + attack-path graph (single-writer, additive) |
| `pipeline.py` | The orchestrator |
| `cli.py` | `analyze` and `findings` commands |

## AST JavaScript analysis

Layered on top of the recon lightweight extractor (not a replacement). Uses
tree-sitter (optional — absent ⇒ graceful fallback). Extracts `fetch`/`axios`/
`WebSocket` calls with methods, route/config objects, `baseURL`, and GraphQL
operations. **Data-flow lite** resolves obvious values only — string constants,
simple aliases, `a + b`, template literals — with strict depth/visited bounds;
dynamic parts become `{dynamic}`/`{name}`. No JavaScript is executed.

## Policy, classification & budgets

Endpoints are classified (authentication, administrative, file-handling,
payment, debug/internal, …) and parameters into families (object-identifier,
access-control, redirect/SSRF, file/path, query/injection, authentication).
These **raise review priority only — never a vulnerability claim**. The policy
engine forces `REVIEW_REQUIRED` for state-changing methods, destructive-looking
paths, sensitive endpoint classes/params and auth operations, and `DISALLOWED`
for logout/session-terminating endpoints and program exclusions.

## Checks & analyzers

Passive checks use stored evidence (no new requests): missing security headers,
version disclosure, weak cookie attributes, observed CORS. SAFE_ACTIVE checks
issue a tiny, benign, non-state-changing number of requests: CORS reflection
(≤3), open-redirect with a benign external sentinel (≤3), method analysis via
`OPTIONS` only (≤1). Asset analyzers: subdomain-takeover **candidate** detection
(provider CNAME + dangling/error signature; never "confirmed", never claims the
resource), OpenAPI security hints, recon-derived exposures (only for
already-discovered URLs — no path guessing), and GraphQL candidates
(introspection OFF by default).

## Access-control differential

With user-provided auth contexts (anonymous / viewer / user / admin), ShadowScan
compares **read-only** responses for the same endpoint and flags: anonymous
receiving a privileged body, sensitive fields visible to a lower context, or
inverted access. Credentials are never obtained or brute-forced; any
state-changing authorization check is `REVIEW_REQUIRED`.

## Finding model & correlation

Findings carry `check_id`, asset, endpoint, parameter, category, confidence,
`validation_state` (`observed` / `suspected` / `validated_non_destructively` /
`manual_validation_required`) and `status` (`new` / `reviewing` / `confirmed` /
`false_positive` / `accepted_risk` / `resolved` / `duplicate`). Findings from the
monitor, a safe check and Nuclei that describe the same issue **deduplicate**
into one finding with multiple evidence sources. Correlation combines findings
with recon context into explainable, bounded review items (e.g. object-id
endpoint + auth-context difference = high authorization review).

## Attack-path graph

Two relational tables (`graph_nodes`, `graph_edges`) — no graph database.
Nodes: asset / service / url / js_file / endpoint / parameter / finding / auth
context. Edges: `DISCOVERED_FROM`, `RUNS_ON`, `USES_PARAMETER`, `SUPPORTED_BY`,
… It answers questions like "which JS file exposed this endpoint?" and "which
endpoints run on this host?".

## AI reasoning (optional)

AI sits above structured evidence and only advises. The provider is abstracted
(`MockProvider` for tests; OpenAI/Anthropic pluggable). Only high-signal items
are sent (`min_priority`, `max_items`, `max_context_bytes`); analyses are cached
by evidence fingerprint so unchanged evidence is never re-analyzed. Prompts
strictly separate SYSTEM POLICY / SHADOWSCAN FACTS / UNTRUSTED TARGET CONTENT /
TASK; output must match a JSON schema (`hypotheses[]` with title/category/
confidence/manual_tests) and is rejected otherwise. AI output is never executed.

## Nuclei integration (optional)

Behind the tool-adapter model: detects the binary, builds argument arrays,
strict timeout, bounded rate/concurrency, and only safe template categories
(`passive`, `exposure`, `misconfig`, `safe_web`). DoS/intrusive/brute-force/
credential/injection tags and `critical` severity are excluded both at launch
and defensively when parsing JSONL into findings.

## CLI

```bash
shadow_scan analyze  --database shadowscan.db --program programs/example.yaml [--scope scope.txt]
                     [--passive-only] [--no-ai] [--auth-context viewer --auth-context admin] [--resume]
shadow_scan findings --database shadowscan.db [--status new ...] [--show ID] [--set ID STATUS]
```

`analyze` reads endpoints from the recon inventory, runs the pipeline and prints
the top findings. `findings` is the triage view: list, `--show ID` (full
evidence + AI hypotheses + manual-validation package), and `--set ID <status>`.

### Example findings view

```
[ 97] Object-level authorization review
      api.example.com  /api/accounts/{account_id}  [validated_non_destructively]
      - anonymous access returns the same privileged response as 'admin'
      AI: Review object-level authorization (confidence 0.6)
          suggested: Compare viewer vs admin responses for the same object id (read-only).
      id=12  source=active,authz_diff

[ 70] CORS behavior: reflected arbitrary origin with credentials
      api.example.com  /api/status  [validated_non_destructively]

[ 40] Manual validation required: PUT /api/users/{id}
      api.example.com  /api/users/{id}  [manual_validation_required]
      - state-changing test intentionally not automated; manual package generated
```

## Program profiles

One YAML per program (`programs/example.yaml`). Secrets are **never** inlined —
auth is referenced via `token_env` / `cookie_env` and the loader rejects any
inlined secret. A profile sets scope, exclusions, allowed ports/methods, global
mode, request/rate budgets, Nuclei profiles, an optional researcher header, and
host-bound auth contexts.

## Security-analysis known limitations

- AST analysis is static (no execution); heavily obfuscated bundles yield less.
- SAFE_ACTIVE checks are intentionally shallow and bounded; deep logic testing is
  left to the manual-validation packages.
- Takeover is candidate-only; ShadowScan never registers or claims resources.
- Access-control differential needs user-supplied, authorized credentials and is
  read-only; BOLA/function-level checks that require mutation are manual.
- AI hypotheses are advisory and may be wrong; they never change policy or act.
- Nuclei results depend on the installed template set; only safe categories run.

---

# Continuous Operations, Program Management, Reporting & Production Hardening

The operations layer (`shadow_scan/ops/`) turns ShadowScan into a daily platform.
It orchestrates the existing monitoring, recon and security-analysis subsystems —
it does not reimplement them — and preserves scope enforcement, policy
enforcement and the single SQLite writer. No automatic exploitation, no automatic
report submission.

Lifecycle: **program → scope → recon → historical comparison → security analysis
→ correlation → AI assistance → research queue → manual validation → finding
management → reporting → continuous monitoring → researcher feedback → next run.**

## Packaging & commands

Installable via `pyproject.toml` with a `shadowscan` console entry point
(`python -m shadow_scan` and `python -m shadow_scan.main` remain compatible):

```bash
pip install -e .            # or: pip install -e ".[ast,dev]"
shadowscan program list
shadowscan program create acme --platform hackerone
shadowscan program validate acme
shadowscan run acme [--resume] [--force] [--insecure]
shadowscan program stats acme
shadowscan findings list --status new
shadowscan db stats|vacuum|integrity|backup|export|import -d runtime/acme/shadowscan.db
shadowscan feedback -d <db> --program acme --kind category --key cookie_security --verdict noise
shadowscan ignore   -d <db> --program acme --add path "*/analytics/*"
shadowscan baseline -d <db> --program acme --add endpoint api.example.com/status "403 expected"
shadowscan schedule acme        # prints Windows/cron/systemd examples
```

## Program workspace model

Config is committed; runtime state (databases, logs, exports, reports) is
git-ignored and isolated per program:

```
programs/acme/program.yaml  scope.yaml  ignore.yaml  auth.example.yaml
runtime/acme/shadowscan.db  logs/  exports/  reports/  run.lock
```

Secrets never live in committed files: auth is referenced by env-var name and
resolved at runtime, bound to a single host, and never stored in SQLite, exports,
logs or notifications. Configuration precedence is
`defaults < global < program < env < CLI`, and a **more restrictive security
policy always wins** (env/global can tighten `global_mode` but a CLI loosening
cannot override a stricter env setting).

## Unified run

`shadowscan run <program>` executes only the stages enabled in the profile:
`preflight → discovery → dns → monitor → services → urls → crawl → javascript →
enrichment → correlation → security_analysis → validation → ai_analysis → review
→ reporting → notifications`. It acquires a program **run lock** (PID + heartbeat,
stale-detection, `--force` recovery), runs **preflight** (Python/DB/config/parsers/
tool health/AI config/writable dirs — no target interaction, degraded mode for
missing optional tools), reuses the existing resumable pipelines, then performs
lifecycle/regression bookkeeping, notifications, the run summary and reports.

## Incremental, retry, guardrails, graceful shutdown

- **Incremental:** per-object evidence fingerprints (`ops_fingerprints`) skip
  unchanged JS/OpenAPI/endpoint/favicon work; each scheduled task records *why*
  (new/changed/forced).
- **Retry:** centralized classification (timeouts/SERVFAIL retryable; NXDOMAIN/403/
  invalid-URL not; policy-denied never) with bounded exponential backoff + jitter —
  no infinite loops.
- **Guardrails:** `MAX_TOTAL_REQUESTS/BYTES/URLS/JS_FILES/AST_BYTES/SECURITY_CHECKS/
  AI_CALLS/RUNTIME` and a disk-space floor; on breach the component stops cleanly,
  is marked limited, and partial results are preserved.
- **Graceful shutdown:** Ctrl+C stops scheduling, lets the DB writer flush, closes
  sessions, marks the run `interrupted` and stays resumable.

## Migrations, backup, export/import

A lightweight ordered, transactional **migration framework** (`schema_migrations`)
coexists with the per-subsystem schema initializers. Databases are migrated, never
deleted. `db backup` uses SQLite's online backup API (never a naive copy).
`db export` writes a versioned JSON envelope of program intelligence that **never
contains secrets** (secret-ish columns are excluded and import validation rejects
any that appear). Retention trims only bulky transient rows, never core findings.

## Researcher feedback, ignore rules, baselines

Deterministic, bounded ranking (no ML): repeated dismissals/"noise" lower a
category/endpoint's priority within `±25`, repeated "interesting"/"confirmed"
raise it. Ignore rules and baselines suppress repetitive noise (and show *why* a
finding was suppressed) but never delete evidence and **never hide structural
attack-surface changes** (new host/endpoint/port/JS route/API doc, takeover,
authorization). Nothing here can override scope or safety policy.

## Finding lifecycle & regression

States: `new → triaged → investigating → confirmed → reported`,
`confirmed → resolved`, plus `duplicate/informative/false_positive/archived`.
Every transition is a non-destructive timeline event. In continuous runs, a
confirmed/reported finding absent from a later run is auto-**resolved**; if it
reappears it is a **regression** — the *same lineage* is reopened (high priority),
never a new duplicate.

## Reporting & report safety

JSON and Markdown run reports and researcher-ready finding drafts (HackerOne /
Bugcrowd / generic formatters). Reports are built from stored, **redacted**
evidence and always distinguish *observed fact* vs *automated hypothesis* vs
*non-destructive validation* vs *manual confirmation*. AI hypotheses are labeled
advisory and are **never** presented as confirmed vulnerabilities; impact is never
fabricated ("manual validation required" when not established).

## Notifications

Providers: console / file / webhook (stdlib only, degrades offline). Events are
structured (`NEW_HIGH_PRIORITY_REVIEW_ITEM`, `NEW_VALIDATED_FINDING`,
`AUTHORIZATION_REVIEW_REQUIRED`, `TAKEOVER_CANDIDATE`, `FINDING_REGRESSED`,
`RUN_COMPLETED`, …), filtered per program (`notify_min_priority` + categories),
deduplicated across runs, and **redacted** — no auth headers, no secrets; webhooks
carry only what identifies the issue. Low-value events default to the run summary.

## Scheduling (Windows first-class)

`shadowscan schedule <program>` prints ready-to-use examples. ShadowScan does not
run an always-on daemon; the OS scheduler invokes a bounded `run` protected by the
run lock, so overlapping schedules cannot collide. Example (Windows Task Scheduler):

```
schtasks /Create /TN "ShadowScan\acme-monitor" /SC HOURLY /MO 4 ^
  /TR "python -m shadow_scan run acme --resume" /RL LIMITED /F
schtasks /Create /TN "ShadowScan\acme-daily" /SC DAILY /ST 03:30 ^
  /TR "python -m shadow_scan run acme" /RL LIMITED /F
```

cron and systemd-timer equivalents are printed too. WSL is not required.

## Examples

### Example program workspace
```
programs/acme/
  program.yaml      # mode, stages, budgets, notify, formatter
  scope.yaml        # scope_roots / excluded_hosts
  ignore.yaml       # ignore/baseline seeds
  auth.example.yaml # env-referenced auth contexts (copy to auth.yaml, git-ignored)
runtime/acme/
  shadowscan.db  logs/  exports/  reports/  run.lock
```

### Example run summary
```
ShadowScan — acme

Run status: completed

  Hosts known:                      4,281
  Resolving:                        3,902
  URLs:                            87,203
  JS assets:                          612
  Endpoints:                        5,140
  Security findings:                   14
  Manual review required:               8
  Validated non-destructively:          3
  Regressions:                          1
  Resolved this run:                    2

Top items:
  [ 98] Possible authorization boundary (api.acme.com)
  [ 94] CORS behavior: reflected arbitrary origin with credentials (app.acme.com)
  [ 91] Previously NXDOMAIN admin host became live (admin-dev.acme.com)

Reports:
  runtime/acme/reports/run-20261008T2030.md
Notifications sent: 4
```

### Example review queue
```
[ 98] Object-level authorization review   api.acme.com  GET /api/accounts/{account_id}
      [validated_non_destructively]  status: confirmed
      - anonymous and viewer receive differing privileged responses
      - account_id is a client-controlled object identifier
      AI: Possible BOLA (confidence 0.62) — compare viewer/admin for same id (read-only)
[ 91] New internal export endpoint         app.acme.com  GET /api/internal/export
      [observed]  status: new
      - introduced by a changed JS bundle; account_id parameter present
```

### Example finding report (Markdown, HackerOne formatter)
```
# Possible authorization boundary

- **Asset:** api.acme.com
- **Endpoint:** /api/accounts/{account_id}
- **Category:** authorization
- **Confidence:** 0.62
- **Validation:** Validated non-destructively (automated, read-only)
- **Status:** confirmed

## Summary
Assembled by ShadowScan from stored evidence. Automated hypotheses are advisory
and are not confirmed vulnerabilities.

## Evidence
- `E1` [diff] anonymous and admin responses are identical across a trust boundary

## Steps To Reproduce
> Suggested, non-destructive manual steps. ShadowScan performs no state-changing tests.
- Request shape: `GET /api/accounts/{account_id}`
- Required auth context: viewer
- Compare viewer vs admin responses for the same object id (read-only).

## Impact
Impact confirmed by manual researcher validation (see timeline).
```

### Example notification (redacted JSON webhook payload)
```json
{"event": "authorization_review_required", "program": "acme",
 "title": "Object-level authorization review", "priority": 98,
 "category": "authorization", "asset": "api.acme.com",
 "detail": {"status": 200}}
```

### Example regression event (timeline)
```
2026-10-01T03:30Z  observed            first observation
2026-10-03T03:30Z  status:confirmed    investigating -> confirmed
2026-10-05T03:30Z  status:resolved     not observed this run (likely fixed)
2026-10-08T03:30Z  finding_regressed   previously resolved finding observed again
```

## Production known limitations

- The unified run reuses the existing pipelines; very large programs should tune
  the per-program budgets/limits and schedule incremental runs frequently.
- The run lock is per program workspace; it does not coordinate across different
  machines sharing a network path (use one scheduler host per program).
- Notification providers beyond console/file/webhook (Slack/Discord/email) are
  intentionally left as thin future additions.
- Docker is optional and not required; Windows-native execution is first-class.
- Feedback adjusts ranking only and is bounded; it never changes scope or policy.
