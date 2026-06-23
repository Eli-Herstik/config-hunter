# config-hunter

A Playwright-based crawler that loads a web app, captures the JSON configs and JS chunks it fetches, and harvests every `http(s)` URL found inside them. Each discovered URL is then probed to classify its authentication scheme (Basic, Bearer, Negotiate/NTLM, OAuth redirect, none, etc.).

## How it works

1. **Crawl** — Launches Chromium via Playwright, navigates to the target URL, and waits for `networkidle`.
2. **Capture** — Intercepts every response that looks like JSON or JS (by `Content-Type` or extension), keeping bodies up to 5 MB.
3. **DOM scan** — Reads `<script type="application/json">` blocks, inline global assignments (`window.__CONFIG = {…}`), and referenced `*.json` assets.
4. **Manifest probe** — Tries well-known build manifest paths (`/asset-manifest.json`, `/manifest.json`, `/.vite/manifest.json`, …) and pulls referenced chunks as text.
5. **Extract** — Recursively walks parsed JSON and falls back to a regex over raw text. JS-object syntax (single quotes, trailing commas, comments) is sanitized before parsing.
6. **Probe** — Issues a `HEAD` (with `GET` fallback on 405) to each discovered URL and classifies the response by status code and `WWW-Authenticate` header. On 403/401 it retries against the host root, since the specific path may block unauthenticated requests while the root reveals the real auth challenge.

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

Provide a session:

```sh
python config_extractor.py https://app.example.com --storage-state auth.json
```

Or pass cookies/headers directly:

```sh
python config_extractor.py https://app.example.com \
    --cookie session=abc123 \
    --header "Authorization: Bearer eyJ…"
```

#### Automatic Keycloak login

On an estate behind a single Keycloak IdP, the crawler can log in itself instead
of being handed a session. Give it credentials and, the first time a navigation
dead-ends on the Keycloak login form, it fills the form, returns to the target,
and rides the silent SSO session into every other app in the same run:

```sh
python config_extractor.py https://app.example.com \
    --keycloak-user alice \
    --keycloak-password s3cret        # or: export KEYCLOAK_PASSWORD=…
```

Pair it with `--storage-state` to use that file as a **session cache**: it's
loaded before crawling when still fresh, and rewritten after a successful login.
So the first run does the login (do it `--headed` once if MFA is enabled), and
later runs reuse the cached session and skip the form entirely:

```sh
python config_extractor.py https://app.example.com \
    --keycloak-user alice --storage-state auth.json
```

Notes and limits:

- Detection keys on the Keycloak login form's stable field ids (`#username`,
  `#password`, `#kc-login`), not a URL pattern — so it survives custom realm
  URLs and themes. Scope it to the IdP origin with `--keycloak-host`.
- Login is attempted **at most once** per crawl; rejected credentials or an MFA
  wall fail fast rather than looping. MFA/OTP can't be scripted — log in once
  `--headed` to populate the cache, then reuse it.
- Without `--storage-state`, login still works; the session just lives in the
  run and isn't cached. With it, the auth-probe pass also reuses the cached
  session automatically.

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
| `--storage-state PATH` | Reuse a saved Playwright session |
| `--cookie KEY=VAL` | Set a cookie (repeatable) |
| `--header "Name: Value"` | Set an extra header (repeatable) |

## Output

Results are emitted only as JSON, via `-o/--output`. Without it the crawl, DNS resolution, and auth-probe passes still run, but only progress lines are printed to the console (which source was captured, how many hosts resolved, how many roots were probed) — nothing is reported. The JSON report contains:

- A `sources` array — each config source (network response, DOM script, JS chunk) with the clean URLs extracted from it and any parse `error`.
- A `suspect_urls` array — URLs quarantined before probing as malformed or templated, each with its `reason` (`bad_host`, `template`) and the sources it came from.
- A `services` map keyed by origin (`scheme://host[:port]`, with the scheme's default port normalized away). A service — not a bare hostname — is the unit of roll-up: two ports on one box, or `http` vs `https`, are treated as distinct services with their own collapsed `auth_method` (`basic`, `bearer`, `negotiate`, `oauth`, `none`, `unknown`, …), `status_codes`, and `notes`, since on an internal estate they usually are. Each entry's `ips` are the resolved addresses for the service's hostname (DNS has no port), so services sharing a host share their IPs.
- An `unresolved_hosts` array — hosts referenced in configs that failed DNS resolution from the scanner's network position (each entry has `host` and an `error` reason such as `NXDOMAIN`, `SERVFAIL`, or `timeout`). URLs on unresolved hosts are skipped during the probe pass.
- An `auth` map keyed by URL — the per-URL probe result (`status_code`, `www_authenticate`, `detected_method`, `note`, `error`). Host roots probed on the scanner's own initiative to disclose an undisclosed scheme are flagged `synthesized`.

## Tests

```sh
pytest
```
