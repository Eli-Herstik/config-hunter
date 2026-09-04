# config-hunter

A Playwright-based crawler that loads a web app, captures the JSON configs and JS chunks it fetches, and harvests every `http(s)` URL found inside them. Each discovered URL is then probed to classify its authentication scheme (Basic, Bearer, Negotiate/NTLM, OAuth redirect, unauthenticated, etc.).

## How it works

1. **Crawl** — Launches Chromium via Playwright, navigates to the target URL, and waits for `networkidle`.
2. **Capture** — Intercepts every response that looks like JSON or JS (by `Content-Type` or extension), keeping bodies up to 5 MB.
3. **DOM scan** — Reads `<script type="application/json">` blocks, inline global assignments (`window.__CONFIG = {…}`), and referenced `*.json` assets.
4. **Manifest probe** — Tries well-known build manifest paths (`/asset-manifest.json`, `/manifest.json`, `/.vite/manifest.json`, …) and pulls referenced chunks as text.
5. **Extract** — Recursively walks parsed JSON and falls back to a regex over raw text. JS-object syntax (single quotes, trailing commas, comments) is sanitized before parsing.
6. **Probe** — Issues a `HEAD` (with `GET` fallback on 405) to each discovered URL and classifies the response by status code and `WWW-Authenticate` header. A response may offer several schemes at once — IIS answers `Negotiate` and `NTLM`, either on repeated header lines or comma-separated in one. An offer is the client's to choose from, so the verdict is the best scheme available rather than the first one listed, and the full offer is kept as evidence. Note this runs opposite to the roll-up across a service's URLs below: a URL offering both `Bearer` and `Basic` is exposable on Bearer, while a service with one Bearer-only URL and one NTLM-only URL is not, since exposing it means exposing both. On 403/401 it retries against the host root, since the specific path may block unauthenticated requests while the root reveals the real auth challenge. The probe always runs anonymous, even when the crawl that found these URLs was authenticated — see below.

## Install

```sh
python -m venv venv
venv\Scripts\activate          # PowerShell: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium
```

## Usage

```sh
python config_extractor.py https://app.example.com
```

Write structured results to a file:

```sh
python config_extractor.py https://app.example.com -o results.json
```

### Authenticated targets

Capture a session interactively with Playwright, then re-use it:

```sh
playwright codegen --save-storage=auth.json https://app.example.com
python config_extractor.py https://app.example.com --storage-state auth.json
```

Or pass cookies/headers directly:

```sh
python config_extractor.py https://app.example.com \
    --cookie session=abc123 \
    --header "Authorization: Bearer eyJ…"
```

All three reach the **crawl only**. The auth probe never sends them, which is
deliberate rather than an omission:

- **It would invert the verdict.** The probe's job is to record what an endpoint
  *demands*. Authenticate it and a gated URL answers 200 and collapses to
  `unauthenticated` — backwards exactly where it costs the most, since an open
  endpoint is the finding that decides whether the F5 may expose the service.

So the session is how you *find* the URLs, not how you *judge* them. A URL only
the authenticated crawl could discover still gets probed cold, and reports the
scheme it puts in front of an anonymous caller.

### Crawling more pages

```sh
python config_extractor.py https://app.example.com --follow-links --max-pages 10
python config_extractor.py https://app.example.com --routes routes.txt
```

A time-budgeted pass of safe scrolls, hovers, and clicks runs on every page to surface lazy-loaded XHRs. Submit buttons, form descendants, and controls labeled "logout"/"delete" are skipped. Tune the budget with `--interact-budget MS`.

### Selected flags

| Flag | Purpose |
|---|---|
| `-o, --output PATH` | Write JSON report (services, auth verdicts, provenance) |
| `--headed` | Show the browser window |
| `--timeout MS` | Navigation timeout (default 30000) |
| `--wait-after-load MS` | Extra idle wait for late XHRs (default 5000) |
| `--follow-links` | Discover same-origin `a[href]` and crawl them |
| `--max-pages N` | Cap pages visited (default 1) |
| `--interact-budget MS` | Per-page interaction budget (default 8000) |
| `--probe-timeout S` / `--probe-concurrency N` | Tune the auth-probe pass |
| `--storage-state PATH` | Reuse a saved Playwright session, crawl only (`playwright codegen --save-storage=…`) |
| `--cookie KEY=VAL` | Set a cookie on the crawl (repeatable) |
| `--header "Name: Value"` | Set an extra header on the crawl (repeatable) |

## Output

Results are emitted only as JSON, via `-o/--output`. Without it the crawl, DNS resolution, and auth-probe passes still run, but only progress lines are printed to the console (which source was captured, how many hosts resolved, how many roots were probed) — nothing is reported. The JSON report contains:

The report indexes by URL throughout: there is no forward array of config sources (network responses, DOM scripts, JS chunks), only the provenance hanging off each URL those sources yielded. Every clean URL reaches the output through `services` or `unresolved_hosts`, so a source is always one dereference away from the endpoint under review rather than the other way round.

- A `source_errors` map — present only when some source's payload failed to parse, giving the decode failure per origin. The message is stored once here; which URLs it affects is recorded on those URLs, as `unparsed_sources`.
- A `suspect_urls` array — URLs quarantined before probing as malformed or templated, each with its `reason` (`bad_host`, `template`) and the sources it came from.
- A `services` map keyed by origin (`scheme://host[:port]`, with the scheme's default port normalized away). A service — not a bare hostname — is the unit of roll-up: two ports on one box, or `http` vs `https`, are treated as distinct services with their own collapsed `auth_verdict` (`basic`, `bearer`, `negotiate`, `oauth`, `unauthenticated`, `unknown`, …, or `null` when every probe failed at the transport), since on an internal estate they usually are. It's a verdict rather than a method because the value is a precedence pick across the service's URLs, not an observation of any one of them — and the precedence is by blocker risk, so when a service's URLs disagree (`mixed`) the headline is the worst thing found: schemes that block exposure (`ntlm`, `basic`, an unrecognized `other`) outrank the ambiguous `negotiate` (Kerberos is fine, NTLM underneath is not), which outranks the schemes that pass review. Each entry's `ips` are the resolved addresses for the service's hostname (DNS has no port), so services sharing a host share their IPs; the map is emitted whether or not the DNS and probe passes ran, being the only place a clean URL is reported, and without them a service is honestly empty-handed — `ips` omitted rather than empty, a null verdict, nothing probed. Each entry's `urls` map holds the per-URL evidence those scalars were collapsed from — `status_code`, `www_authenticate`, `location`, `detected_method`, `error`, with null fields omitted — which is how you find the one open endpoint on a `mixed` service, the raw challenge behind an `other` verdict (or the full set of them, comma-joined, when the response offered more than one), whether an `oauth` verdict points at an external IdP or at an ADFS box on the estate, or why a probe failed at the transport. A host root probed on the scanner's own initiative to disclose an undisclosed scheme is listed there too, flagged `synthesized` so the report never implies the app referenced `/`. Nothing on a gated path points back at it: the root's verdict is reported as the root's own entry and nowhere else, so what it implies about a sibling path is left to the reader. Every URL a config referenced also carries `sources`, the origins it was extracted from, so provenance sits where the exposure decision is made rather than a search away. It is plural because one URL is routinely compiled into several bundles, and that fan-out separates a URL the app genuinely calls from a string that only a vendor chunk mentions — the distinction the probe evidence alone can't make. A `synthesized` root has no `sources`: no config named it. A URL also carries `unparsed_sources` when some of those origins never parsed — the subset of its own `sources` whose payload was expected to be JSON, wasn't, and so was regex-scraped out of unstructured text instead. It qualifies confidence in the URL rather than saying anything about the endpoint: a URL listing all of its sources there was never seen inside a structure anything could parse. `js:` bundles are always scraped by regex and never appear, their origin prefix having already said so, and the field is omitted when every source parsed.
- An `unresolved_hosts` array, present only when the resolution pass ran (an empty array would otherwise claim every host resolved) — hosts referenced in configs that failed DNS resolution from the scanner's network position (each entry has `host` and an `error` reason such as `NXDOMAIN`, `SERVFAIL`, or `timeout`). URLs on unresolved hosts are skipped during the probe pass, and so are absent from `services`, which covers only hosts that resolved; each entry therefore carries the `urls` behind its failed lookup, in the same per-URL shape a service uses, which for a URL nothing probed is its provenance alone. They are grouped by hostname because that is what DNS failed on — one bad name takes down every scheme and port that would otherwise have been its own service — and the key is omitted for a host no clean URL named. On an internal estate a name that doesn't resolve is worth chasing, and the path and provenance are what make it actionable.

## Tests

```sh
pytest
```
