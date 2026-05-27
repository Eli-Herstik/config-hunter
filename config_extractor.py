"""
Config Extractor - Playwright crawler that extracts URLs from web app JSON configurations.

Navigates to a web app, intercepts JSON config files (network responses + DOM),
and harvests all HTTP/HTTPS URLs found within them.
"""

import argparse
import asyncio
import json
import re
import socket
import string
import sys
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import aiohttp

from playwright.async_api import async_playwright, Response, Page

MAX_PAYLOAD_BYTES = 5 * 1024 * 1024  # 5 MB


@dataclass
class ConfigSource:
    origin: str
    raw_text: str = ""
    json_payload: object = None
    urls_found: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class ProbeResult:
    """Auth evidence from HTTP probing."""
    url: str
    status_code: int | None
    www_authenticate: str | None
    detected_method: str | None  # "basic" | "bearer" | "negotiate" | "none" | "unknown" | "forbidden"
    error: str | None = None


@dataclass
class AuthInfo:
    """Auth info for a single URL, derived from HTTP probing."""
    url: str
    probe_result: ProbeResult | None = None
    best_guess: str = "unknown"


# ---------------------------------------------------------------------------
# HTTP probing
# ---------------------------------------------------------------------------

def _parse_www_authenticate(header: str) -> str:
    """Extract the auth scheme from a WWW-Authenticate header value."""
    scheme = header.strip().split()[0].lower() if header else ""
    mapping = {"basic": "basic", "bearer": "bearer", "negotiate": "negotiate", "ntlm": "negotiate"}
    return mapping.get(scheme, scheme or "unknown")


def _host_root_url(url: str) -> str | None:
    """Return scheme://host[:port]/ if the URL has a path beyond /, else None."""
    parsed = urlparse(url)
    if parsed.path and parsed.path.rstrip("/"):
        root = f"{parsed.scheme}://{parsed.netloc}/"
        return root
    return None


async def _do_probe_request(
    session: aiohttp.ClientSession,
    url: str,
    timeout: float,
) -> tuple[int, str | None, str]:
    """Make a HEAD (or GET fallback) request. Return (status_code, www_authenticate, location)."""
    async with session.head(url, timeout=aiohttp.ClientTimeout(total=timeout),
                            allow_redirects=False) as resp:
        status = resp.status
        if status == 405:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                                   allow_redirects=False) as resp2:
                return (resp2.status,
                        resp2.headers.get("WWW-Authenticate"),
                        resp2.headers.get("Location", ""))
        return status, resp.headers.get("WWW-Authenticate"), resp.headers.get("Location", "")


def _classify_probe(status: int, www_auth: str | None, location: str = "") -> str:
    """Classify a probe response into a detected auth method string."""
    if status == 401:
        return _parse_www_authenticate(www_auth) if www_auth else "unknown"
    if status == 403:
        return "forbidden"
    if 200 <= status < 300:
        return "none"
    if 300 <= status < 400:
        if any(kw in location.lower() for kw in ("oauth", "authorize", "login", "auth")):
            return "oauth"
        return "redirect"
    if status == 400:
        return "bad_request"
    if status == 404:
        return "not_found"
    if status == 407:
        return "proxy_auth"
    if 500 <= status < 600:
        return "server_error"
    return "unknown"


async def _probe_single(
    session: aiohttp.ClientSession,
    url: str,
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> ProbeResult:
    """Probe a single URL for auth requirements."""
    async with semaphore:
        try:
            status, www_auth, location = await _do_probe_request(session, url, timeout)
            method = _classify_probe(status, www_auth, location)

            # On 400/403/404, the specific path may not work or may block
            # unauthenticated requests — the host root can still reveal
            # the service's auth requirements more clearly
            if status in (400, 403, 404):
                root = _host_root_url(url)
                if root:
                    try:
                        root_status, root_www_auth, root_location = await _do_probe_request(session, root, timeout)
                        root_method = _classify_probe(root_status, root_www_auth, root_location)
                        # Use root result if it reveals auth info
                        if root_method not in ("bad_request", "forbidden", "not_found", "server_error", "unknown"):
                            return ProbeResult(
                                url=url,
                                status_code=root_status,
                                www_authenticate=root_www_auth,
                                detected_method=root_method,
                            )
                    except Exception:
                        pass  # root fallback failed, keep original result

            return ProbeResult(
                url=url,
                status_code=status,
                www_authenticate=www_auth,
                detected_method=method,
            )
        except Exception as e:
            return ProbeResult(
                url=url,
                status_code=None,
                www_authenticate=None,
                detected_method=None,
                error=str(e),
            )


async def probe_urls(
    urls: list[str],
    timeout: float = 5.0,
    max_concurrent: int = 10,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> list[ProbeResult]:
    """Probe a list of URLs for authentication requirements."""
    unique_urls = list(dict.fromkeys(urls))  # deduplicate, preserve order
    semaphore = asyncio.Semaphore(max_concurrent)
    merged_headers = {"User-Agent": "ConfigExtractor/1.0", **(headers or {})}
    session_kwargs: dict = {"headers": merged_headers}
    if cookies:
        session_kwargs["cookies"] = cookies
    async with aiohttp.ClientSession(**session_kwargs) as session:
        tasks = [_probe_single(session, url, semaphore, timeout) for url in unique_urls]
        return await asyncio.gather(*tasks)


def merge_probe_results(auth_map: dict[str, AuthInfo], probes: list[ProbeResult]) -> None:
    """Merge probe results into the auth map."""
    for probe in probes:
        if probe.url in auth_map:
            auth_map[probe.url].probe_result = probe


def reconcile_auth(auth_map: dict[str, AuthInfo]) -> None:
    """Set best_guess on each AuthInfo from its probe result."""
    for info in auth_map.values():
        probe = info.probe_result
        if probe and probe.www_authenticate:
            info.best_guess = _parse_www_authenticate(probe.www_authenticate)
        elif probe and probe.status_code and 200 <= probe.status_code < 300:
            info.best_guess = "none"
        elif probe and probe.detected_method and probe.detected_method not in ("unknown", "forbidden", None):
            info.best_guess = probe.detected_method
        elif probe and probe.detected_method == "forbidden":
            info.best_guess = "unknown (forbidden)"
        # else: stays "unknown"


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

def _classify_dns_error(exc: BaseException) -> str:
    if isinstance(exc, asyncio.TimeoutError):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        if exc.errno == socket.EAI_NONAME:
            return "NXDOMAIN"
        if exc.errno == socket.EAI_AGAIN:
            return "SERVFAIL"
        return f"gaierror: {exc.strerror or exc}"
    return str(exc)


async def _resolve_single(
    host: str,
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> dict | None:
    """Resolve one host; return {host, error} on failure, None on success."""
    loop = asyncio.get_running_loop()
    async with semaphore:
        try:
            await asyncio.wait_for(
                loop.getaddrinfo(host, None),
                timeout=timeout,
            )
            return None
        except Exception as e:
            return {"host": host, "error": _classify_dns_error(e)}


async def resolve_hosts(
    hosts: list[str],
    timeout: float = 3.0,
    max_concurrent: int = 20,
) -> list[dict]:
    """Resolve each host via the system resolver; return [{host, error}] for failures only."""
    unique_hosts = list(dict.fromkeys(hosts))
    semaphore = asyncio.Semaphore(max_concurrent)
    tasks = [_resolve_single(h, semaphore, timeout) for h in unique_hosts]
    results = await asyncio.gather(*tasks)
    failures = [r for r in results if r is not None]
    failures.sort(key=lambda r: r["host"])
    return failures


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

URL_RE = re.compile(r'https?://[^\s"\'<>}\]\)]+')


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:)\\")


_VALID_HOSTNAME_CHARS = set(string.ascii_letters + string.digits + ".-")


def _classify_url(url: str) -> str | None:
    """Return a 'suspect' reason if the URL should be quarantined, else None."""
    if "${" in url or "`" in url:
        return "template"
    host = urlparse(url).hostname
    if not host:
        return "bad_host"
    if not all(c in _VALID_HOSTNAME_CHARS for c in host):
        return "bad_host"
    return None


def _partition_urls(urls: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """Split URLs into (clean, [(suspect_url, reason), ...])."""
    clean: list[str] = []
    suspect: list[tuple[str, str]] = []
    for u in urls:
        reason = _classify_url(u)
        if reason is None:
            clean.append(u)
        else:
            suspect.append((u, reason))
    return clean, suspect


def extract_urls(obj, seen: set[str] | None = None) -> list[str]:
    """Recursively extract http/https URLs from a parsed JSON structure."""
    if seen is None:
        seen = set()
    urls: list[str] = []

    if isinstance(obj, str):
        for m in URL_RE.findall(obj):
            clean = _clean_url(m)
            if clean not in seen:
                seen.add(clean)
                urls.append(clean)
    elif isinstance(obj, dict):
        for v in obj.values():
            urls.extend(extract_urls(v, seen))
    elif isinstance(obj, list):
        for item in obj:
            urls.extend(extract_urls(item, seen))
    return urls


def extract_urls_from_text(text: str) -> list[str]:
    """Regex fallback: pull URLs directly from raw text."""
    seen: set[str] = set()
    urls: list[str] = []
    for m in URL_RE.findall(text):
        clean = _clean_url(m)
        if clean not in seen:
            seen.add(clean)
            urls.append(clean)
    return urls


# ---------------------------------------------------------------------------
# JSON sanitization (JS object -> JSON best-effort)
# ---------------------------------------------------------------------------

def sanitize_js_object(text: str) -> str:
    text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)   # line comments
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)   # block comments
    text = re.sub(r"'", '"', text)                            # single -> double quotes
    text = re.sub(r",\s*([}\]])", r"\1", text)               # trailing commas
    return text


def try_parse_json(text: str) -> tuple[object | None, str | None]:
    """Try to parse text as JSON, with JS-object sanitization fallback."""
    try:
        return json.loads(text), None
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        return json.loads(sanitize_js_object(text)), None
    except (json.JSONDecodeError, ValueError) as e:
        return None, str(e)


# ---------------------------------------------------------------------------
# Network interception
# ---------------------------------------------------------------------------

def _is_json_response(response: Response) -> bool:
    ct = response.headers.get("content-type", "")
    if "json" in ct:
        return True
    if response.url.split("?")[0].split("#")[0].endswith(".json"):
        return True
    return False


def _is_js_response(response: Response) -> bool:
    ct = response.headers.get("content-type", "").lower()
    if "javascript" in ct or "ecmascript" in ct:
        return True
    path = response.url.split("?")[0].split("#")[0]
    if path.endswith((".js", ".mjs", ".cjs")):
        return True
    return False


def _exceeds_size_limit(response: Response) -> bool:
    cl = response.headers.get("content-length", "")
    if cl.isdigit() and int(cl) > MAX_PAYLOAD_BYTES:
        return True
    return False


async def capture_response(
    response: Response,
    captured_json: list[tuple[str, str]],
    captured_js: list[tuple[str, str]],
    seen_urls: set[str],
) -> None:
    if response.status < 200 or response.status >= 300:
        return
    if response.url in seen_urls:
        return
    if _exceeds_size_limit(response):
        print(f"  [skip] Response too large: {response.url}", file=sys.stderr)
        return
    is_json = _is_json_response(response)
    is_js = not is_json and _is_js_response(response)
    if not (is_json or is_js):
        return
    try:
        body = await response.text()
        if len(body) > MAX_PAYLOAD_BYTES:
            print(f"  [skip] Body too large: {response.url}", file=sys.stderr)
            return
        if is_json:
            captured_json.append((response.url, body))
        else:
            captured_js.append((response.url, body))
        seen_urls.add(response.url)
    except Exception:
        pass  # body unavailable (e.g. page navigated away)


def process_network_captures(captured: list[tuple[str, str]]) -> list[ConfigSource]:
    sources: list[ConfigSource] = []
    for url, body in captured:
        parsed, err = try_parse_json(body)
        if parsed is not None:
            urls = extract_urls(parsed)
        else:
            urls = extract_urls_from_text(body)
        if urls:
            sources.append(ConfigSource(
                origin=f"network: {url}",
                raw_text=body[:200],
                json_payload=parsed,
                urls_found=urls,
                error=err,
            ))
    return sources


def process_js_captures(captured: list[tuple[str, str]]) -> list[ConfigSource]:
    """Extract URLs from captured JS bodies via regex (no JSON parsing)."""
    sources: list[ConfigSource] = []
    for url, body in captured:
        urls = extract_urls_from_text(body)
        if urls:
            sources.append(ConfigSource(
                origin=f"js: {url}",
                raw_text=body[:200],
                json_payload=None,
                urls_found=urls,
                error=None,
            ))
    return sources


# ---------------------------------------------------------------------------
# DOM scanning
# ---------------------------------------------------------------------------

# Regex to find JS variable assignments that look like config objects/arrays
CONFIG_ASSIGN_RE = re.compile(
    r'(?:window\.[\w.]+|(?:var|let|const)\s+\w+)\s*=\s*(\{[\s\S]*\}|\[[\s\S]*\])\s*;',
)


async def extract_from_dom(page: Page, captured_urls: set[str]) -> list[ConfigSource]:
    sources: list[ConfigSource] = []

    # Strategy A: <script type="application/json">
    for el in await page.query_selector_all('script[type="application/json"]'):
        text = (await el.inner_text()).strip()
        if not text:
            continue
        parsed, err = try_parse_json(text)
        if parsed is not None:
            urls = extract_urls(parsed)
        else:
            urls = extract_urls_from_text(text)
        if urls:
            sources.append(ConfigSource(
                origin="dom: <script type=\"application/json\">",
                raw_text=text[:200],
                json_payload=parsed,
                urls_found=urls,
                error=err,
            ))

    # Strategy B: inline scripts with global variable assignments
    for el in await page.query_selector_all("script:not([src])"):
        script_type = await el.get_attribute("type")
        if script_type and script_type != "text/javascript":
            continue
        text = (await el.inner_text()).strip()
        if not text or len(text) < 10:
            continue
        for match in CONFIG_ASSIGN_RE.finditer(text):
            json_str = match.group(1)
            parsed, err = try_parse_json(json_str)
            if parsed is not None:
                urls = extract_urls(parsed)
            else:
                urls = extract_urls_from_text(json_str)
            if urls:
                # Identify which variable was assigned
                assign_text = text[max(0, match.start() - 40):match.start() + 60]
                assign_label = assign_text.split("=")[0].strip()[-40:]
                sources.append(ConfigSource(
                    origin=f"dom: inline script ({assign_label})",
                    raw_text=json_str[:200],
                    json_payload=parsed,
                    urls_found=urls,
                    error=err,
                ))

    # Strategy C: <script src="*.json"> or <link href="*.json">
    for el in await page.query_selector_all(
        'script[src$=".json"], link[href$=".json"]'
    ):
        src = await el.get_attribute("src") or await el.get_attribute("href")
        if not src:
            continue
        abs_url = urljoin(page.url, src)
        if abs_url in captured_urls:
            continue  # already captured via network interception
        try:
            resp = await page.context.request.get(abs_url)
            body = await resp.text()
            parsed, err = try_parse_json(body)
            if parsed is not None:
                urls = extract_urls(parsed)
            else:
                urls = extract_urls_from_text(body)
            if urls:
                sources.append(ConfigSource(
                    origin=f"dom: referenced file {src}",
                    raw_text=body[:200],
                    json_payload=parsed,
                    urls_found=urls,
                    error=err,
                ))
        except Exception as e:
            print(f"  [warn] Could not fetch {abs_url}: {e}", file=sys.stderr)

    return sources


# ---------------------------------------------------------------------------
# Interaction simulation
# ---------------------------------------------------------------------------

# Text/attribute patterns that mark a control as risky to click during crawling
_DANGER_TEXT_RE = re.compile(r"sign\s*out|log\s*out|delete|remove|destroy", re.IGNORECASE)


async def _safe_wait_idle(page: Page, timeout_ms: int = 1000) -> None:
    try:
        await page.wait_for_load_state("networkidle", timeout=timeout_ms)
    except Exception:
        pass


async def _is_safe_to_click(el) -> bool:
    """Heuristic: skip submit buttons, danger text, cross-origin links, form descendants."""
    try:
        text = (await el.inner_text()).strip() if await el.is_visible() else ""
    except Exception:
        return False
    if text and _DANGER_TEXT_RE.search(text):
        return False
    try:
        in_form = await el.evaluate("el => !!el.closest('form')")
        if in_form:
            return False
    except Exception:
        return False
    try:
        type_attr = (await el.get_attribute("type")) or ""
        if type_attr.lower() == "submit":
            return False
    except Exception:
        pass
    try:
        testid = (await el.get_attribute("data-testid")) or ""
        if "logout" in testid.lower() or "signout" in testid.lower():
            return False
    except Exception:
        pass
    return True


async def _run_interactions(page: Page, budget_ms: int) -> None:
    """Generic, time-budgeted interactions to surface lazy/click-triggered XHRs."""
    deadline = asyncio.get_event_loop().time() + budget_ms / 1000.0

    def time_left() -> bool:
        return asyncio.get_event_loop().time() < deadline

    # Step 1: incremental scroll
    if time_left():
        try:
            for _ in range(4):
                if not time_left():
                    break
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await page.wait_for_timeout(250)
            await _safe_wait_idle(page)
        except Exception as e:
            print(f"  [warn] scroll failed: {e}", file=sys.stderr)

    # Step 2: hover top-level nav (route prefetch)
    if time_left():
        try:
            nav_locator = page.locator("nav a, header a, [role=menuitem]")
            count = min(await nav_locator.count(), 6)
            for i in range(count):
                if not time_left():
                    break
                try:
                    await nav_locator.nth(i).hover(timeout=500)
                except Exception:
                    pass
            await _safe_wait_idle(page)
        except Exception as e:
            print(f"  [warn] hover failed: {e}", file=sys.stderr)

    # Step 3: click visible safe controls (buttons, tabs, disclosures)
    if time_left():
        try:
            click_locator = page.locator(
                "button:not([type=submit]), [role=tab], [aria-expanded=false]"
            )
            count = min(await click_locator.count(), 8)
            for i in range(count):
                if not time_left():
                    break
                el = click_locator.nth(i)
                try:
                    if not await el.is_visible():
                        continue
                    if not await _is_safe_to_click(el):
                        continue
                    await el.click(timeout=750, trial=True)
                    await el.click(timeout=1500, no_wait_after=True)
                    await _safe_wait_idle(page, timeout_ms=750)
                    try:
                        await page.keyboard.press("Escape")
                    except Exception:
                        pass
                except Exception:
                    continue
        except Exception as e:
            print(f"  [warn] click pass failed: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Crawler orchestrator
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Drop fragment and normalize trailing slash on path for dedupe purposes."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    # Reconstruct without fragment
    netloc = parsed.netloc
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme}://{netloc}{path}{query}"


async def _discover_links(page: Page, base_url: str, same_origin_only: bool) -> list[str]:
    """Pull a[href] values from the page; return absolute http(s) URLs."""
    try:
        hrefs = await page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.getAttribute('href'))"
        )
    except Exception:
        return []
    base_host = urlparse(base_url).netloc
    out: list[str] = []
    for href in hrefs:
        if not href:
            continue
        if href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        abs_url = urljoin(base_url, href)
        parsed = urlparse(abs_url)
        if parsed.scheme not in ("http", "https"):
            continue
        if same_origin_only and parsed.netloc != base_host:
            continue
        out.append(abs_url)
    return out


# ---------------------------------------------------------------------------
# Asset manifest probing
# ---------------------------------------------------------------------------

# Well-known manifest paths that bundlers expose
MANIFEST_PATHS = (
    "/asset-manifest.json",          # Create React App
    "/manifest.json",                # generic
    "/.vite/manifest.json",          # Vite (production manifest)
    "/build/manifest.json",          # Remix / some Vite setups
    "/static/manifest.json",         # generic /static prefix
)

# Match webpack/Vite-style chunk references inside manifest JSON / _buildManifest.js
_CHUNK_LIKE_RE = re.compile(r'["\']([^"\']*\.(?:m?js|cjs))["\']')


def _extract_chunk_paths_from_manifest(text: str) -> list[str]:
    """Pull plausible chunk paths out of a manifest body (JSON or JS)."""
    paths: list[str] = []
    seen: set[str] = set()

    parsed, _ = try_parse_json(text)
    if parsed is not None:
        def walk(node):
            if isinstance(node, str):
                if node.endswith((".js", ".mjs", ".cjs")) and node not in seen:
                    seen.add(node)
                    paths.append(node)
            elif isinstance(node, dict):
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
        walk(parsed)

    # Always also regex-scan: handles _buildManifest.js (not JSON) and JSON
    # values where chunk paths are embedded in templated strings.
    for m in _CHUNK_LIKE_RE.findall(text):
        if m and m not in seen:
            seen.add(m)
            paths.append(m)

    return paths


async def _probe_manifests(
    context,
    base_url: str,
    captured_js: list[tuple[str, str]],
    captured_json: list[tuple[str, str]],
    seen_urls: set[str],
) -> int:
    """Try well-known manifest paths; fetch any referenced chunks as text.
    Returns number of chunks captured."""
    chunks_added = 0

    for manifest_rel in MANIFEST_PATHS:
        manifest_url = urljoin(base_url, manifest_rel)
        if manifest_url in seen_urls:
            continue
        try:
            resp = await context.request.get(manifest_url, timeout=5000)
            if resp.status < 200 or resp.status >= 300:
                continue
            body = await resp.text()
        except Exception:
            continue
        if not body or len(body) > MAX_PAYLOAD_BYTES:
            continue

        # SPAs typically serve their index.html with 200 for any unknown
        # path. Only treat the response as a manifest if it's actually JSON
        # by content-type or by parseability.
        ct = resp.headers.get("content-type", "").lower()
        parsed_manifest, _ = try_parse_json(body)
        if "json" not in ct and parsed_manifest is None:
            continue

        # The manifest itself often contains URLs worth harvesting
        captured_json.append((manifest_url, body))
        seen_urls.add(manifest_url)
        print(f"  [manifest] {manifest_url}")

        chunk_paths = _extract_chunk_paths_from_manifest(body)
        for chunk_path in chunk_paths:
            chunk_abs = urljoin(manifest_url, chunk_path)
            if chunk_abs in seen_urls:
                continue
            try:
                cresp = await context.request.get(chunk_abs, timeout=5000)
                if cresp.status < 200 or cresp.status >= 300:
                    continue
                cbody = await cresp.text()
                if not cbody or len(cbody) > MAX_PAYLOAD_BYTES:
                    continue
                captured_js.append((chunk_abs, cbody))
                seen_urls.add(chunk_abs)
                chunks_added += 1
            except Exception:
                continue

    return chunks_added


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------

_LOGIN_URL_RE = re.compile(r"/(login|signin|sign-in|auth/(?:login|signin)|sso)\b", re.IGNORECASE)


def _cookies_from_kv(items: list[str], seed_url: str) -> list[dict]:
    """Parse 'key=value' strings into Playwright cookie dicts.
    Domain is inferred from the seed URL's host."""
    host = urlparse(seed_url).hostname or ""
    cookies: list[dict] = []
    for item in items:
        if "=" not in item:
            print(f"  [warn] Ignoring malformed --cookie {item!r} (expected key=value)", file=sys.stderr)
            continue
        name, _, value = item.partition("=")
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        cookies.append({
            "name": name,
            "value": value,
            "domain": host,
            "path": "/",
        })
    return cookies


def _headers_from_kv(items: list[str]) -> dict[str, str]:
    """Parse 'Name: Value' strings into a header dict."""
    headers: dict[str, str] = {}
    for item in items:
        if ":" not in item:
            print(f"  [warn] Ignoring malformed --header {item!r} (expected Name: Value)", file=sys.stderr)
            continue
        name, _, value = item.partition(":")
        name = name.strip()
        value = value.strip()
        if name:
            headers[name] = value
    return headers


def _storage_state_to_probe_cookies(path: str, seed_url: str) -> dict[str, str]:
    """Read a Playwright storage-state JSON and extract cookies for the seed host
    as a flat {name: value} dict suitable for aiohttp.ClientSession(cookies=...)."""
    host = urlparse(seed_url).hostname or ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"  [warn] Could not read storage-state {path}: {e}", file=sys.stderr)
        return {}
    out: dict[str, str] = {}
    for c in data.get("cookies", []):
        cookie_domain = (c.get("domain") or "").lstrip(".")
        if not cookie_domain or host == cookie_domain or host.endswith("." + cookie_domain):
            name = c.get("name")
            value = c.get("value")
            if name is not None and value is not None:
                out[name] = value
    return out


async def _run_login_capture(url: str, save_path: str) -> None:
    """Open a headed browser, wait for the user to log in, save storage state, exit."""
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=False)
        context = await browser.new_context()
        page = await context.new_page()
        try:
            await page.goto(url)
        except Exception as e:
            print(f"  [warn] Initial navigation issue: {e}", file=sys.stderr)
        print(f"\n  Log in in the browser window, then press Enter here to save the session to {save_path} ...")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, input)
        await context.storage_state(path=save_path)
        await browser.close()
        print(f"Saved storage state to {save_path}.")


def _check_auth_signal(seed_url: str, final_url: str, status: int | None,
                      www_authenticate: str | None) -> str | None:
    """Return a warning string if the seed page looks unauthenticated, else None."""
    seed_host = urlparse(seed_url).hostname or ""
    final_host = urlparse(final_url).hostname or ""
    if status == 401:
        return f"entry page returned 401 (URL: {final_url})."
    if www_authenticate:
        return f"entry page sent WWW-Authenticate: {www_authenticate} (URL: {final_url})."
    if seed_host and final_host and seed_host != final_host:
        return f"entry page redirected off-origin to {final_url}."
    if _LOGIN_URL_RE.search(final_url):
        return f"final URL looks like a login page: {final_url}."
    return None


async def _crawl_one_page(
    context,
    url: str,
    captured: list[tuple[str, str]],
    captured_js: list[tuple[str, str]],
    captured_urls: set[str],
    seen_urls: set[str],
    timeout: int,
    wait_after_load: int,
    interact_budget_ms: int,
    is_seed: bool = False,
) -> tuple[list[ConfigSource], list[str]]:
    """Visit one URL; return (dom_sources, discovered_links)."""
    page = await context.new_page()
    page.on("response", lambda resp: asyncio.ensure_future(
        capture_response(resp, captured, captured_js, seen_urls)
    ))

    print(f"Navigating to {url} ...")
    response = None
    try:
        response = await page.goto(url, wait_until="networkidle", timeout=timeout)
    except Exception as e:
        print(f"  [warn] Navigation issue for {url}: {e}", file=sys.stderr)

    if is_seed:
        status = response.status if response else None
        www_auth = response.headers.get("www-authenticate") if response else None
        signal = _check_auth_signal(url, page.url, status, www_auth)
        if signal:
            print(f"  [auth] {signal} Try --login or refresh --storage-state.", file=sys.stderr)

    if wait_after_load > 0:
        await page.wait_for_timeout(wait_after_load)

    print(f"  Running interactions (budget {interact_budget_ms}ms)...")
    await _run_interactions(page, interact_budget_ms)
    if wait_after_load > 0:
        await page.wait_for_timeout(wait_after_load)

    dom_sources = await extract_from_dom(page, captured_urls)

    discovered: list[str] = []
    try:
        discovered = await _discover_links(page, page.url, same_origin_only=True)
    except Exception:
        pass

    await page.close()
    return dom_sources, discovered


async def crawl(
    url: str | list[str],
    timeout: int = 30000,
    wait_after_load: int = 5000,
    headed: bool = False,
    interact_budget_ms: int = 8000,
    follow_links: bool = False,
    max_pages: int = 1,
    same_origin_only: bool = True,
    storage_state: str | None = None,
    extra_http_headers: dict[str, str] | None = None,
    cookies: list[dict] | None = None,
) -> list[ConfigSource]:
    if isinstance(url, str):
        seeds = [url]
    else:
        seeds = list(url)
    if not seeds:
        return []

    captured: list[tuple[str, str]] = []
    captured_js: list[tuple[str, str]] = []
    # Dedup set: shared across page captures and the manifest probe so the
    # same chunk URL never appears twice in captured_js / captured_json.
    seen_urls: set[str] = set()
    all_dom_sources: list[ConfigSource] = []

    queue: list[str] = []
    visited: set[str] = set()
    for s in seeds:
        norm = _normalize_url(s)
        if norm not in visited:
            visited.add(norm)
            queue.append(s)

    seed_host = urlparse(seeds[0]).netloc

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=not headed)
        context_kwargs: dict = {}
        if storage_state:
            context_kwargs["storage_state"] = storage_state
        if extra_http_headers:
            context_kwargs["extra_http_headers"] = extra_http_headers
        context = await browser.new_context(**context_kwargs)
        if cookies:
            await context.add_cookies(cookies)

        pages_visited = 0
        manifest_probed = False
        while queue and pages_visited < max_pages:
            current = queue.pop(0)
            captured_urls = {u for u, _ in captured}
            dom_sources, discovered = await _crawl_one_page(
                context=context,
                url=current,
                captured=captured,
                captured_js=captured_js,
                captured_urls=captured_urls,
                seen_urls=seen_urls,
                timeout=timeout,
                wait_after_load=wait_after_load,
                interact_budget_ms=interact_budget_ms,
                is_seed=(pages_visited == 0),
            )
            all_dom_sources.extend(dom_sources)
            pages_visited += 1

            # Manifest probe — once, after the first page renders, against the seed origin
            if not manifest_probed:
                manifest_probed = True
                added = await _probe_manifests(context, seeds[0], captured_js, captured, seen_urls)
                if added:
                    print(f"  [manifest] captured {added} chunk(s)")

            if follow_links and pages_visited < max_pages:
                for link in discovered:
                    if same_origin_only and urlparse(link).netloc != seed_host:
                        continue
                    norm = _normalize_url(link)
                    if norm in visited:
                        continue
                    visited.add(norm)
                    queue.append(link)

        await browser.close()

    print(f"Captured {len(captured)} JSON network responses across {pages_visited} page(s).")
    print(f"Captured {len(captured_js)} JS bodies (chunks/manifests).")

    network_sources = process_network_captures(captured)
    js_sources = process_js_captures(captured_js)
    return network_sources + js_sources + all_dom_sources


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_results(
    sources: list[ConfigSource],
    auth_map: dict[str, AuthInfo] | None = None,
    unresolved: list[dict] | None = None,
) -> None:
    if not sources:
        print("\nNo JSON configurations with URLs were found.")
        return

    all_clean: set[str] = set()
    suspect_count = 0
    print(f"\n{'=' * 70}")
    for src in sources:
        clean, suspect = _partition_urls(src.urls_found)
        suspect_count += len(suspect)
        print(f"\n  Source: {src.origin}")
        if src.error:
            print(f"  (JSON parse error — used regex fallback: {src.error})")
        print(f"  URLs found: {len(clean)}")
        for u in clean:
            print(f"    {u}")
            all_clean.add(u)
    hosts: set[str] = set()
    for u in all_clean:
        host = urlparse(u).hostname
        if host:
            hosts.add(host)
    sorted_hosts = sorted(hosts)

    print(f"\n{'=' * 70}")
    print(f"Total config sources: {len(sources)}")
    print(f"Total unique URLs:    {len(all_clean)}")
    if sorted_hosts:
        print(f"\nUnique hosts ({len(sorted_hosts)}):")
        for h in sorted_hosts:
            print(f"    {h}")
    print(f"{'=' * 70}")

    # Auth analysis section
    if auth_map:
        print(f"\n{'=' * 70}")
        print("Authentication Analysis")
        print(f"{'=' * 70}")
        for url in sorted(auth_map):
            info = auth_map[url]
            print(f"\n  {url}")
            if info.probe_result:
                probe = info.probe_result
                if probe.error:
                    print(f"    Probe:   error — {probe.error}")
                elif probe.www_authenticate:
                    print(f"    Probe:   {probe.status_code} — WWW-Authenticate: {probe.www_authenticate}")
                else:
                    label = probe.detected_method or "unknown"
                    print(f"    Probe:   {probe.status_code} — {label}")
            print(f"    Verdict: {info.best_guess}")
        print(f"\n{'=' * 70}")

    if suspect_count:
        print(f"\nSuspect URLs (skipped probe): {suspect_count}")

    if unresolved:
        print(f"\nUnresolved hosts (skipped probe): {len(unresolved)}")

    print()


def write_results(
    sources: list[ConfigSource],
    path: str,
    auth_map: dict[str, AuthInfo] | None = None,
    unresolved: list[dict] | None = None,
) -> None:
    all_clean: set[str] = set()
    suspect_index: dict[str, dict] = {}
    entries = []
    for src in sources:
        clean, suspect = _partition_urls(src.urls_found)
        entries.append({
            "source": src.origin,
            "urls": clean,
            "error": src.error,
        })
        all_clean.update(clean)
        for url, reason in suspect:
            entry = suspect_index.setdefault(url, {"reason": reason, "sources": []})
            if src.origin not in entry["sources"]:
                entry["sources"].append(src.origin)

    hosts: set[str] = set()
    for u in all_clean:
        host = urlparse(u).hostname
        if host:
            hosts.add(host)

    suspect_urls = [
        {"url": url, "reason": entry["reason"], "sources": entry["sources"]}
        for url, entry in sorted(suspect_index.items())
    ]

    output: dict = {
        "sources": entries,
        "unique_hosts": sorted(hosts),
        "suspect_urls": suspect_urls,
    }

    if unresolved is not None:
        output["unresolved_hosts"] = unresolved

    if auth_map:
        auth_section: dict = {}
        for url, info in sorted(auth_map.items()):
            entry: dict = {"best_guess": info.best_guess}
            if info.probe_result:
                p = info.probe_result
                entry["probe"] = {
                    "status_code": p.status_code,
                    "www_authenticate": p.www_authenticate,
                    "detected_method": p.detected_method,
                    "error": p.error,
                }
            auth_section[url] = entry
        output["auth"] = auth_section

    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"Results written to {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract URLs from a web app's JSON configuration files.",
    )
    parser.add_argument("url", help="Target web app URL")
    parser.add_argument("-o", "--output", help="Write results to a JSON file")
    parser.add_argument(
        "--timeout", type=int, default=30000,
        help="Navigation timeout in ms (default: 30000)",
    )
    parser.add_argument(
        "--wait-after-load", type=int, default=5000,
        help="Extra wait time in ms for lazy XHR (default: 5000)",
    )
    parser.add_argument(
        "--headed", action="store_true",
        help="Run browser in headed mode (visible window)",
    )
    parser.add_argument(
        "--probe-timeout", type=int, default=5,
        help="Per-URL probe timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--probe-concurrency", type=int, default=10,
        help="Max concurrent probe requests (default: 10)",
    )
    parser.add_argument(
        "--routes", type=str, default=None,
        help="Path to a file with extra seed URLs (one per line)",
    )
    parser.add_argument(
        "--login", action="store_true",
        help="Open a headed browser, wait for manual login, save the session, and exit",
    )
    parser.add_argument(
        "--save-storage", type=str, default="auth.json",
        help="Output path for --login mode (default: auth.json)",
    )
    parser.add_argument(
        "--storage-state", type=str, default=None,
        help="Load a Playwright storage-state JSON before crawling",
    )
    parser.add_argument(
        "--cookie", action="append", default=[],
        help="Set a cookie KEY=VAL (repeatable). Domain inferred from URL.",
    )
    parser.add_argument(
        "--header", action="append", default=[],
        help='Send an extra HTTP header "Name: Value" (repeatable).',
    )
    parser.add_argument(
        "--follow-links", action="store_true",
        help="Auto-discover same-origin links from each crawled page",
    )
    parser.add_argument(
        "--max-pages", type=int, default=1,
        help="Cap pages visited (default: 1, single-URL behaviour)",
    )
    parser.add_argument(
        "--cross-origin", action="store_true",
        help="Allow follow-links to jump origins (default: same-origin only)",
    )
    parser.add_argument(
        "--interact-budget", type=int, default=8000,
        help="Per-page interaction budget in ms (default: 8000)",
    )
    args = parser.parse_args()

    if args.login:
        asyncio.run(_run_login_capture(args.url, args.save_storage))
        return

    seeds: list[str] = [args.url]
    if args.routes:
        try:
            with open(args.routes, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        seeds.append(line)
        except OSError as e:
            print(f"  [error] Could not read --routes file: {e}", file=sys.stderr)
            sys.exit(2)

    cli_cookies = _cookies_from_kv(args.cookie, args.url)
    cli_headers = _headers_from_kv(args.header)

    sources = asyncio.run(crawl(
        url=seeds if len(seeds) > 1 else args.url,
        timeout=args.timeout,
        wait_after_load=args.wait_after_load,
        headed=args.headed,
        interact_budget_ms=args.interact_budget,
        follow_links=args.follow_links,
        max_pages=args.max_pages,
        same_origin_only=not args.cross_origin,
        storage_state=args.storage_state,
        extra_http_headers=cli_headers or None,
        cookies=cli_cookies or None,
    ))

    all_urls: list[str] = []
    for src in sources:
        all_urls.extend(src.urls_found)
    unique_urls = [u for u in dict.fromkeys(all_urls) if _classify_url(u) is None]
    auth_map: dict[str, AuthInfo] = {url: AuthInfo(url=url) for url in unique_urls}

    probe_cookies: dict[str, str] = {}
    if args.storage_state:
        probe_cookies.update(_storage_state_to_probe_cookies(args.storage_state, args.url))
    for c in cli_cookies:
        probe_cookies[c["name"]] = c["value"]

    unresolved: list[dict] = []
    probeable_urls = unique_urls
    if unique_urls:
        unique_url_hosts = sorted({urlparse(u).hostname for u in unique_urls if urlparse(u).hostname})
        print(f"Resolving {len(unique_url_hosts)} hosts...")
        unresolved = asyncio.run(resolve_hosts(unique_url_hosts))
        unresolved_set = {entry["host"] for entry in unresolved}
        if unresolved_set:
            probeable_urls = [u for u in unique_urls if urlparse(u).hostname not in unresolved_set]
            for url in unique_urls:
                if urlparse(url).hostname in unresolved_set:
                    auth_map[url].best_guess = "unknown (unresolved host)"

    if probeable_urls:
        skipped = len(unique_urls) - len(probeable_urls)
        skip_msg = f" (skipping {skipped} on unresolved hosts)" if skipped else ""
        print(f"Probing {len(probeable_urls)} URLs for authentication methods...{skip_msg}")
        probes = asyncio.run(probe_urls(
            probeable_urls,
            timeout=float(args.probe_timeout),
            max_concurrent=args.probe_concurrency,
            cookies=probe_cookies or None,
            headers=cli_headers or None,
        ))
        merge_probe_results(auth_map, probes)
        reconcile_auth(auth_map)

    print_results(sources, auth_map, unresolved)

    if args.output:
        write_results(sources, args.output, auth_map, unresolved)


if __name__ == "__main__":
    main()
