# config-hunter

A Playwright-based crawler that loads a web app, captures the JSON configs and JS chunks it fetches, and harvests every `http(s)` URL found inside them. Each discovered URL is then probed to classify its authentication scheme (Basic, Bearer, Negotiate/NTLM, OAuth redirect, unauthenticated, etc.).

## How it works

1. **Crawl** — Launches Chromium via Playwright, navigates to the target URL, and waits for `networkidle`.
2. **Capture** — Intercepts every response that looks like JSON or JS (by `Content-Type` or extension), keeping bodies up to 5 MB.
3. **DOM scan** — Reads `<script type="application/json">` blocks, inline global assignments (`window.__CONFIG = {…}`), and referenced `*.json` assets.
4. **Manifest probe** — Tries well-known build manifest paths (`/asset-manifest.json`, `/manifest.json`, `/.vite/manifest.json`, …) and pulls referenced chunks as text.
5. **Extract** — Recursively walks parsed JSON and falls back to a regex over raw text. JS-object syntax (single quotes, trailing commas, comments) is sanitized before parsing.
6. **Probe** — Issues a `HEAD` (with `GET` fallback on 405) to each discovered URL and classifies the response by status code and `WWW-Authenticate` header. A response may offer several schemes at once — IIS answers `Negotiate` and `NTLM`, either on repeated header lines or comma-separated in one — and since the client picks, the verdict is the highest-risk scheme offered rather than the first one listed. On 403/401 it retries against the host root, since the specific path may block unauthenticated requests while the root reveals the real auth challenge.

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

### Crawling more pages

```sh
python config_extractor.py https://app.example.com --follow-links --max-pages 10
python config_extractor.py https://app.example.com --routes routes.txt
```

A time-budgeted pass of safe scrolls, hovers, and clicks runs on every page to surface lazy-loaded XHRs. Submit buttons, form descendants, and controls labeled "logout"/"delete" are skipped. Tune the budget with `--interact-budget MS`.

### Selected flags

| Flag | Purpose |
|---|---|
| `-o, --output PATH` | Write JSON report (sources, services, auth verdicts) |
| `--headed` | Show the browser window |
| `--timeout MS` | Navigation timeout (default 30000) |
| `--wait-after-load MS` | Extra idle wait for late XHRs (default 5000) |
| `--follow-links` | Discover same-origin `a[href]` and crawl them |
| `--max-pages N` | Cap pages visited (default 1) |
| `--interact-budget MS` | Per-page interaction budget (default 8000) |
| `--probe-timeout S` / `--probe-concurrency N` | Tune the auth-probe pass |
| `--storage-state PATH` | Reuse a saved Playwright session (`playwright codegen --save-storage=…`) |
| `--cookie KEY=VAL` | Set a cookie (repeatable) |
| `--header "Name: Value"` | Set an extra header (repeatable) |

## Output

Results are emitted only as JSON, via `-o/--output`. Without it the crawl, DNS resolution, and auth-probe passes still run, but only progress lines are printed to the console (which source was captured, how many hosts resolved, how many roots were probed) — nothing is reported. The JSON report contains:

- A `sources` array — each config source (network response, DOM script, JS chunk) with the clean URLs extracted from it and any parse `error`.
- A `suspect_urls` array — URLs quarantined before probing as malformed or templated, each with its `reason` (`bad_host`, `template`) and the sources it came from.
- A `services` map keyed by origin (`scheme://host[:port]`, with the scheme's default port normalized away). A service — not a bare hostname — is the unit of roll-up: two ports on one box, or `http` vs `https`, are treated as distinct services with their own collapsed `auth_verdict` (`basic`, `bearer`, `negotiate`, `oauth`, `unauthenticated`, `unknown`, …, or `null` when every probe failed at the transport), since on an internal estate they usually are. It's a verdict rather than a method because the value is a precedence pick across the service's URLs, not an observation of any one of them — and the precedence is by blocker risk, so when a service's URLs disagree (`mixed`) the headline is the worst thing found: schemes that block exposure (`ntlm`, `basic`, an unrecognized `other`) outrank the ambiguous `negotiate` (Kerberos is fine, NTLM underneath is not), which outranks the schemes that pass review. Each entry's `ips` are the resolved addresses for the service's hostname (DNS has no port), so services sharing a host share their IPs. Each entry's `urls` map holds the per-URL evidence those scalars were collapsed from — `status_code`, `www_authenticate`, `location`, `detected_method`, `root_discloses`, `error`, with null fields omitted — which is how you find the one open endpoint on a `mixed` service, the raw challenge behind an `other` verdict (or the full set of them, comma-joined, when the response offered more than one), whether an `oauth` verdict points at an external IdP or at an ADFS box on the estate, or why a probe failed at the transport. A gated path whose 401/403 named no scheme carries `root_discloses`, the verdict its *own* origin's root answered (`unauthenticated` meaning the front door is open) — the nearest thing to an explanation for a path that disclosed nothing itself, and the only link back to the root's own entry. A 400 never carries it: "rejected before auth could be evaluated" says nothing about how the path is guarded. A host root probed on the scanner's own initiative to disclose an undisclosed scheme is listed there too, flagged `synthesized` so the report never implies the app referenced `/`.
- An `unresolved_hosts` array — hosts referenced in configs that failed DNS resolution from the scanner's network position (each entry has `host` and an `error` reason such as `NXDOMAIN`, `SERVFAIL`, or `timeout`). URLs on unresolved hosts are skipped during the probe pass.

## Tests

```sh
pytest
```
