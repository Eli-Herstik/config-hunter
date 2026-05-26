# config-hunter

A Playwright-based crawler that loads a web app, captures the JSON configs and JS chunks it fetches, and harvests every `http(s)` URL found inside them. Each discovered URL is then probed to classify its authentication scheme (Basic, Bearer, Negotiate/NTLM, OAuth redirect, none, etc.).

## How it works

1. **Crawl** — Launches Chromium via Playwright, navigates to the target URL, and waits for `networkidle`.
2. **Capture** — Intercepts every response that looks like JSON or JS (by `Content-Type` or extension), keeping bodies up to 5 MB.
3. **DOM scan** — Reads `<script type="application/json">` blocks, inline global assignments (`window.__CONFIG = {…}`), and referenced `*.json` assets.
4. **Manifest probe** — Tries well-known build manifest paths (`/asset-manifest.json`, `/manifest.json`, `/.vite/manifest.json`, …) and pulls referenced chunks as text.
5. **Extract** — Recursively walks parsed JSON and falls back to a regex over raw text. JS-object syntax (single quotes, trailing commas, comments) is sanitized before parsing.
6. **Probe** — Issues a `HEAD` (with `GET` fallback on 405) to each discovered URL and classifies the response by status code and `WWW-Authenticate` header. On 400/403/404 it retries against the host root, since the specific path may block unauthenticated requests while the root reveals the real auth challenge.

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

Capture a session interactively, then re-use it:

```sh
python config_extractor.py https://app.example.com --login --save-storage auth.json
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
| `-o, --output PATH` | Write JSON report (sources, hosts, auth verdicts) |
| `--headed` | Show the browser window |
| `--timeout MS` | Navigation timeout (default 30000) |
| `--wait-after-load MS` | Extra idle wait for late XHRs (default 5000) |
| `--follow-links` | Discover same-origin `a[href]` and crawl them |
| `--max-pages N` | Cap pages visited (default 1) |
| `--cross-origin` | Allow `--follow-links` to leave the seed origin |
| `--interact-budget MS` | Per-page interaction budget (default 8000) |
| `--no-capture-js` | Skip JS chunk capture |
| `--no-manifest-probe` | Skip well-known manifest paths |
| `--probe-timeout S` / `--probe-concurrency N` | Tune the auth-probe pass |
| `--login` / `--save-storage PATH` | Headed manual-login capture mode |
| `--storage-state PATH` | Reuse a saved Playwright session |
| `--cookie KEY=VAL` | Set a cookie (repeatable) |
| `--header "Name: Value"` | Set an extra header (repeatable) |

## Output

The console report lists each config source (network response, DOM script, JS chunk), the URLs extracted from it, the unique host set, and an "Authentication Analysis" section with a per-URL probe result and verdict (`basic`, `bearer`, `negotiate`, `oauth`, `none`, `unknown`, …). With `-o`, the same data is written as JSON, including an `unresolved_hosts` array — hosts referenced in configs that failed DNS resolution from the scanner's network position (each entry has `host` and an `error` reason such as `NXDOMAIN`, `SERVFAIL`, or `timeout`). URLs on unresolved hosts are skipped during the probe pass.

## Tests

```sh
pytest
```
