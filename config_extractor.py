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
import ssl
import string
import sys
from dataclasses import dataclass, field
from enum import StrEnum
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


class AuthMethod(StrEnum):
    """Closed vocabulary for an auth verdict. A StrEnum so members compare
    equal to and serialize as their lowercase string value."""
    BASIC = "basic"
    BEARER = "bearer"
    NEGOTIATE = "negotiate"
    NTLM = "ntlm"
    # An uncommon but well-formed challenge scheme (Digest, vendor schemes, ...).
    # The specific scheme is named in ProbeResult.note; the raw header is also
    # preserved in ProbeResult.www_authenticate.
    OTHER = "other"
    OAUTH = "oauth"
    LOGIN_REDIRECT = "login_redirect"
    NONE = "none"
    UNKNOWN = "unknown"


@dataclass
class ProbeResult:
    """Auth evidence from HTTP probing."""
    url: str
    status_code: int | None
    www_authenticate: str | None
    # Auth verdict, an AuthMethod (one of BASIC/BEARER/NEGOTIATE/NTLM/OTHER/
    # OAUTH/LOGIN_REDIRECT/NONE/UNKNOWN). None only on transport error (see
    # `error`).
    detected_method: AuthMethod | None
    # Short human-readable context, set when the verdict is inconclusive or
    # coarse — e.g. "forbidden (403)", "not found (404)", "server error: 503
    # Service Unavailable", "challenge scheme: digest" (naming an OTHER verdict),
    # "redirects off-origin to sso.corp.local". None when the verdict already
    # says everything (a named scheme, NONE, a clean redirect). Distinct from
    # `error`, which is reserved for transport failures (a 5xx is a successful
    # HTTP transaction, so it lands here).
    note: str | None = None
    error: str | None = None


@dataclass
class AuthInfo:
    """Auth info for a single URL, derived from HTTP probing."""
    url: str
    probe_result: ProbeResult | None = None
    # True when this entry is a host root we probed on our own initiative — no
    # config referenced it — to disclose the scheme behind a 401/403 path that
    # gave no WWW-Authenticate. Kept distinct so the output never implies the
    # app referenced `/` when it didn't. NOT load-bearing for the host-verdict
    # collapse (the precedence order handles masking); purely provenance.
    synthesized: bool = False


# ---------------------------------------------------------------------------
# HTTP probing
# ---------------------------------------------------------------------------

def _parse_www_authenticate(header: str) -> tuple[AuthMethod, str | None]:
    """Extract the auth scheme from a WWW-Authenticate header value, as
    (method, note). A known challenge scheme maps to its AuthMethod with no
    note; an unrecognized but well-formed scheme is OTHER with the scheme named
    in the note; a truthy-but-tokenless header is UNKNOWN (a case the old
    `scheme or "unknown"` swallowed silently)."""
    scheme = header.strip().split()[0].lower() if header.strip() else ""
    known = {"basic", "bearer", "negotiate", "ntlm"}
    if scheme in known:
        return AuthMethod(scheme), None
    if scheme:
        return AuthMethod.OTHER, f"challenge scheme: {scheme}"
    return AuthMethod.UNKNOWN, "malformed WWW-Authenticate"


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
) -> tuple[int, str | None, str, str]:
    """Make a HEAD (or GET fallback) request.
    Return (status_code, www_authenticate, location, reason_phrase)."""
    async with session.head(url, timeout=aiohttp.ClientTimeout(total=timeout),
                            allow_redirects=False) as resp:
        status = resp.status
        if status == 405:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                                   allow_redirects=False) as resp2:
                return (resp2.status,
                        resp2.headers.get("WWW-Authenticate"),
                        resp2.headers.get("Location", ""),
                        resp2.reason or "")
        return (status,
                resp.headers.get("WWW-Authenticate"),
                resp.headers.get("Location", ""),
                resp.reason or "")


def _classify_redirect(location: str, url: str) -> tuple[AuthMethod, str | None]:
    """Sub-classify a 3xx response into (detected_method, note).

    An auth-flagged redirect is a real auth verdict (OAUTH / LOGIN_REDIRECT);
    a plain route change is not a method, so it returns UNKNOWN with a note
    describing where it points."""
    if not location:
        return AuthMethod.UNKNOWN, "redirect (no Location header)"
    has_keyword = any(kw in location.lower()
                      for kw in ("oauth", "authorize", "login", "auth"))
    # Compare the redirect target's host to the probed host. A federated
    # SSO/OAuth flow points off-host (login.microsoftonline.com, an ADFS
    # box, sso.corp.local); a local form-login points back at the same
    # origin. Resolve first — servers commonly send a relative Location
    # like "/login", whose hostname is empty until joined with the URL.
    target = urljoin(url, location)
    target_host = (urlparse(target).hostname or "").lower()
    probed_host = (urlparse(url).hostname or "").lower()
    off_host = bool(target_host) and target_host != probed_host
    if has_keyword:
        return (AuthMethod.OAUTH, None) if off_host else (AuthMethod.LOGIN_REDIRECT, None)
    if off_host:
        return AuthMethod.UNKNOWN, f"redirects off-origin to {target_host}"
    return AuthMethod.UNKNOWN, f"redirects to {target}"


def _classify_probe(status: int, www_auth: str | None, location: str = "",
                    url: str = "", reason: str = "") -> tuple[AuthMethod, str | None]:
    """Classify a probe response into (detected_method, note).

    detected_method is an AuthMethod verdict; note is a short human-readable
    string set only when the verdict is inconclusive or coarse (why we couldn't
    pin a method, a heads-up like a proxy / off-origin redirect, or the specific
    scheme behind an OTHER verdict); it is None otherwise."""
    # A WWW-Authenticate challenge is authoritative on any status, not just
    # 401. RFC 6750 (OAuth Bearer) returns it on 403 for insufficient_scope,
    # and the header MAY appear on other statuses per RFC 7235 §4.1.
    if www_auth:
        return _parse_www_authenticate(www_auth)
    if status == 401:
        # Auth is required, but the server didn't disclose the scheme.
        return AuthMethod.UNKNOWN, "auth required, scheme undisclosed"
    if status == 403:
        return AuthMethod.UNKNOWN, "forbidden (403)"
    if 200 <= status < 300:
        return AuthMethod.NONE, None
    if 300 <= status < 400:
        return _classify_redirect(location, url)
    if status == 400:
        return AuthMethod.UNKNOWN, "bad request (400)"
    if status == 404:
        return AuthMethod.UNKNOWN, "not found (404)"
    if status == 407:
        return AuthMethod.UNKNOWN, "proxy authentication required (407)"
    if 500 <= status < 600:
        detail = f"{status} {reason}".strip()
        return AuthMethod.UNKNOWN, f"server error: {detail}"
    detail = f"{status} {reason}".strip()
    return AuthMethod.UNKNOWN, f"unexpected status {detail}"


def _classify_probe_error(exc: BaseException) -> str:
    """Render a transport error from probing as a short, non-empty reason.

    Mirrors _classify_dns_error. aiohttp's `total` timeout raises a bare
    asyncio.TimeoutError whose str() is the empty string, so a plain str(exc)
    would leave ProbeResult.error uninformative (""). Bucket the common cases
    and always fall back to a non-empty representation."""
    if isinstance(exc, asyncio.TimeoutError):
        # Also catches aiohttp.ServerTimeoutError (a subclass); the headline is
        # "timeout" regardless of which clock (total/connect/read) fired.
        return "timeout"
    if isinstance(exc, ssl.SSLError):
        reason = getattr(exc, "reason", None)
        return f"TLS error: {reason}" if reason else "TLS error"
    if isinstance(exc, aiohttp.ClientConnectorError):
        # The wrapped OSError carries the actionable detail (connection
        # refused, no route to host, ...).
        os_err = getattr(exc, "os_error", None)
        if os_err is not None:
            return f"connection failed: {os_err.strerror or os_err}"
        return f"connection failed: {exc}"
    if isinstance(exc, aiohttp.ServerDisconnectedError):
        return "server disconnected"
    if isinstance(exc, aiohttp.ClientConnectionError):
        return f"connection error: {exc}".rstrip(": ")
    return str(exc) or repr(exc)


async def _probe_single(
    session: aiohttp.ClientSession,
    url: str,
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> ProbeResult:
    """Probe a single URL for auth requirements. Returns the path's own verdict;
    host-root enrichment is handled separately by probe_urls_with_roots."""
    async with semaphore:
        try:
            status, www_auth, location, reason = await _do_probe_request(session, url, timeout)
            method, note = _classify_probe(status, www_auth, location, url, reason)
            return ProbeResult(
                url=url,
                status_code=status,
                www_authenticate=www_auth,
                detected_method=method,
                note=note,
            )
        except Exception as e:
            return ProbeResult(
                url=url,
                status_code=None,
                www_authenticate=None,
                detected_method=None,
                error=_classify_probe_error(e),
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


async def probe_urls_with_roots(
    urls: list[str],
    *,
    timeout: float = 5.0,
    max_concurrent: int = 10,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[list[ProbeResult], list[ProbeResult]]:
    """Probe `urls`, then for any host with a path we couldn't read (400/401/403,
    scheme not named) probe that host's root once to try to disclose the scheme.

    The root probe fires on three statuses but they mean different things:
    401/403 establish "this path is gated, scheme undisclosed" — so we also drop
    a breadcrumb linking the path to the front door that explains it. A 400
    ("rejected before auth could be evaluated" — WAF, wrong verb/content-type,
    SNI) establishes no such thing about the path, so it triggers the root probe
    (the host is alive and its front door is a useful fact) but gets NO
    breadcrumb — "host root discloses X" on a malformed-request path would be an
    unfounded inference.

    Returns (path_probes, root_probes). root_probes are for synthesized
    host-root URLs not already in `urls`, filtered to those that disclosed
    something useful (a concrete scheme, or NONE = 'front door open'); UNKNOWN
    or errored roots add nothing and are dropped. The path keeps its own
    verdict — the root is never substituted into it."""
    kw = dict(timeout=timeout, max_concurrent=max_concurrent,
              cookies=cookies, headers=headers)
    path_probes = await probe_urls(urls, **kw)

    def triggers_root(p: ProbeResult) -> bool:
        return p.status_code in (400, 401, 403) and p.detected_method is AuthMethod.UNKNOWN

    def gets_breadcrumb(p: ProbeResult) -> bool:
        return p.status_code in (401, 403) and p.detected_method is AuthMethod.UNKNOWN

    probed = set(urls)
    roots: list[str] = []
    seen: set[str] = set()
    for p in path_probes:
        if triggers_root(p):
            root = _host_root_url(p.url)
            if root and root not in probed and root not in seen:
                seen.add(root)
                roots.append(root)

    root_probes: list[ProbeResult] = []
    if roots:
        raw = await probe_urls(roots, **kw)
        root_probes = [r for r in raw
                       if r.detected_method is not None
                       and r.detected_method is not AuthMethod.UNKNOWN]

    # Breadcrumb: point each undisclosed *gated* path (401/403) at the front door
    # that explains it, since once the root is a separate entry nothing else links
    # them in the per-URL view. 400 paths trigger the probe but get no breadcrumb.
    disclosed = {urlparse(r.url).hostname: r.detected_method for r in root_probes}
    for p in path_probes:
        if gets_breadcrumb(p):
            m = disclosed.get(urlparse(p.url).hostname)
            if m is not None:
                hint = ("; host root is open (none)" if m is AuthMethod.NONE
                        else f"; host root discloses {m.value}")
                p.note = (p.note or "") + hint
    return path_probes, root_probes


def merge_probe_results(auth_map: dict[str, AuthInfo], probes: list[ProbeResult]) -> None:
    """Merge probe results into the auth map."""
    for probe in probes:
        if probe.url in auth_map:
            auth_map[probe.url].probe_result = probe


def merge_root_probes(auth_map: dict[str, AuthInfo], root_probes: list[ProbeResult]) -> None:
    """Insert host-root probes as new auth_map entries. If the root URL is
    already a key, the config genuinely referenced it — fold the probe in and
    leave `synthesized` False, so a discovered root is treated like any other
    discovered URL."""
    for probe in root_probes:
        existing = auth_map.get(probe.url)
        if existing is None:
            auth_map[probe.url] = AuthInfo(
                url=probe.url, probe_result=probe, synthesized=True)
        elif existing.probe_result is None:
            existing.probe_result = probe


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
) -> dict:
    """Resolve one host; return {host, ips} on success or {host, error} on failure.
    `ips` is the distinct resolved addresses (IPv4 + IPv6), sorted."""
    loop = asyncio.get_running_loop()
    async with semaphore:
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, None),
                timeout=timeout,
            )
            # getaddrinfo yields (family, type, proto, canonname, sockaddr);
            # sockaddr[0] is the address string for both AF_INET and AF_INET6.
            ips = sorted({info[4][0] for info in infos})
            return {"host": host, "ips": ips}
        except Exception as e:
            return {"host": host, "error": _classify_dns_error(e)}


async def resolve_hosts(
    hosts: list[str],
    timeout: float = 3.0,
    max_concurrent: int = 20,
) -> tuple[list[dict], dict[str, list[str]]]:
    """Resolve each host via the system resolver.

    Return (failures, ip_map): `failures` is [{host, error}] for hosts that
    failed to resolve (sorted by host); `ip_map` is {host: [ip, ...]} for those
    that resolved."""
    unique_hosts = list(dict.fromkeys(hosts))
    semaphore = asyncio.Semaphore(max_concurrent)
    tasks = [_resolve_single(h, semaphore, timeout) for h in unique_hosts]
    results = await asyncio.gather(*tasks)
    failures = [r for r in results if "error" in r]
    failures.sort(key=lambda r: r["host"])
    ip_map = {r["host"]: r["ips"] for r in results if "ips" in r}
    return failures, ip_map


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


async def _discover_links(page: Page, base_url: str) -> list[str]:
    """Pull a[href] values from the page; return absolute same-origin http(s) URLs."""
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
        if parsed.netloc != base_host:
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
        discovered = await _discover_links(page, page.url)
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

# Precedence for collapsing a host's per-URL auth verdicts into one headline
# method. Earlier wins: a concrete challenge scheme is the most informative
# answer to "how does this service authenticate", redirect-based flows come
# next, NONE ("definitively open") below those, and UNKNOWN ("inconclusive")
# last so it never masks a real verdict. Transport errors (detected_method is
# None) are not auth verdicts — they're counted as `unreachable`, not ranked.
_VERDICT_PRECEDENCE: tuple[AuthMethod, ...] = (
    AuthMethod.NEGOTIATE,
    AuthMethod.NTLM,
    AuthMethod.BEARER,
    AuthMethod.BASIC,
    AuthMethod.OTHER,
    AuthMethod.OAUTH,
    AuthMethod.LOGIN_REDIRECT,
    # UNKNOWN outranks NONE on purpose: a path we couldn't clear (401/403,
    # scheme undisclosed) is the thing a reader must look at before exposure.
    # If NONE won, one open endpoint (often the host root) would mask a
    # restricted sibling in the host headline — the false negative this scan
    # exists to catch. A concrete scheme still outranks both.
    AuthMethod.UNKNOWN,
    AuthMethod.NONE,
)


def _collapse_host_verdict(verdicts: set[AuthMethod]) -> AuthMethod | None:
    """Pick the single headline AuthMethod for a host from the distinct verdicts
    seen across its probed URLs, by _VERDICT_PRECEDENCE. Returns None when there
    are no auth verdicts (e.g. every probe hit a transport error)."""
    for method in _VERDICT_PRECEDENCE:
        if method in verdicts:
            return method
    return None


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _service_key(url: str) -> str | None:
    """Normalize a URL to its origin (scheme://host[:port]) — the identity we
    roll auth verdicts up by. On an internal estate a hostname is not a service:
    two ports on one box, or http vs https, are usually distinct services with
    their own auth, and collapsing them by bare hostname would hide a gated
    sibling behind an open one. The scheme's default port is stripped so
    https://h and https://h:443 (and http://h / http://h:80) name one service,
    not two. Returns None if the URL has no host."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return None
    try:
        port = parsed.port
    except ValueError:  # out-of-range port; treat as unspecified
        port = None
    if port is not None and port != _DEFAULT_PORTS.get(parsed.scheme):
        return f"{parsed.scheme}://{host}:{port}"
    return f"{parsed.scheme}://{host}"


def write_results(
    sources: list[ConfigSource],
    path: str,
    auth_map: dict[str, AuthInfo] | None = None,
    unresolved: list[dict] | None = None,
    ip_map: dict[str, list[str]] | None = None,
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

    services: set[str] = set()
    for u in all_clean:
        svc = _service_key(u)
        if svc:
            services.add(svc)

    # Per-service roll-up of the auth probes: one collapsed verdict per service,
    # where a service is an origin (scheme://host[:port], default port stripped —
    # see _service_key), not a bare hostname, so two ports on one box or http vs
    # https don't merge. Restricted to services whose host passed DNS resolution
    # (full inventory minus the DNS failures). DNS has no notion of port, so the
    # resolution check and `ips` are looked up through the service's *hostname*
    # component: `ips` is the distinct resolved addresses (IPv4 + IPv6, sorted)
    # for that host — it can map to several (round-robin DNS, load balancers,
    # dual-stack), and shared IPs across services reveal a common backend.
    # `auth_method` is the highest-precedence AuthMethod seen across the
    # service's probed URLs (see _VERDICT_PRECEDENCE); `status_codes` lists the
    # distinct HTTP statuses observed — the evidence behind the verdict, and what
    # disambiguates an `unknown` service (403 vs 404 vs 503); `notes` maps each
    # probed URL that carried an inconclusive/coarse note to that note (the
    # scheme behind an `other`, a redirect target, why a method couldn't be
    # pinned) — the service-scoped view the flat `auth` section can't give, and
    # which endpoint disagreed when `mixed`; `mixed` flags a service whose URLs
    # disagreed; and `unreachable` counts URLs that resolved but failed to probe
    # (transport error, no status), so a DNS-OK-but-dead service isn't misread as
    # "no auth".
    unresolved_set = {e["host"] for e in unresolved} if unresolved else set()
    resolved_services = {s for s in services
                         if urlparse(s).hostname not in unresolved_set}

    service_probes: dict[str, list[tuple[str, ProbeResult | None]]] = {}
    if auth_map:
        for url, info in auth_map.items():
            svc = _service_key(url)
            if not svc:
                continue
            service_probes.setdefault(svc, []).append((url, info.probe_result))

    services_section: dict = {}
    for svc in sorted(resolved_services):
        probes = service_probes.get(svc, [])
        auth_verdicts = {p.detected_method for _, p in probes
                         if p and p.detected_method is not None}
        hostname = urlparse(svc).hostname
        services_section[svc] = {
            "ips": (ip_map or {}).get(hostname, []),
            "auth_method": _collapse_host_verdict(auth_verdicts),
            "status_codes": sorted({p.status_code for _, p in probes
                                    if p and p.status_code is not None}),
            "notes": {url: p.note for url, p in sorted(probes) if p and p.note},
            "mixed": len(auth_verdicts) > 1,
            "urls_probed": len(probes),
            "unreachable": sum(1 for _, p in probes
                               if not p or p.detected_method is None),
        }

    suspect_urls = [
        {"url": url, "reason": entry["reason"], "sources": entry["sources"]}
        for url, entry in sorted(suspect_index.items())
    ]

    output: dict = {
        "sources": entries,
        "suspect_urls": suspect_urls,
    }

    if unresolved is not None:
        output["services"] = services_section
        output["unresolved_hosts"] = unresolved

    if auth_map:
        auth_section: dict = {}
        for url, info in sorted(auth_map.items()):
            entry: dict = {}
            if info.synthesized:
                entry["synthesized"] = True
            if info.probe_result:
                p = info.probe_result
                entry["probe"] = {
                    "status_code": p.status_code,
                    "www_authenticate": p.www_authenticate,
                    "detected_method": p.detected_method,
                    "note": p.note,
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
        storage_state=args.storage_state,
        extra_http_headers=cli_headers or None,
        cookies=cli_cookies or None,
    ))

    all_urls: list[str] = []
    for src in sources:
        all_urls.extend(src.urls_found)
    unique_urls = [u for u in dict.fromkeys(all_urls) if _classify_url(u) is None]

    probe_cookies: dict[str, str] = {}
    if args.storage_state:
        probe_cookies.update(_storage_state_to_probe_cookies(args.storage_state, args.url))
    for c in cli_cookies:
        probe_cookies[c["name"]] = c["value"]

    unresolved: list[dict] = []
    ip_map: dict[str, list[str]] = {}
    probeable_urls = unique_urls
    if unique_urls:
        unique_url_hosts = sorted({urlparse(u).hostname for u in unique_urls if urlparse(u).hostname})
        print(f"Resolving {len(unique_url_hosts)} hosts...")
        unresolved, ip_map = asyncio.run(resolve_hosts(unique_url_hosts))
        unresolved_set = {entry["host"] for entry in unresolved}
        if unresolved_set:
            probeable_urls = [u for u in unique_urls if urlparse(u).hostname not in unresolved_set]

    auth_map: dict[str, AuthInfo] = {url: AuthInfo(url=url) for url in probeable_urls}

    if probeable_urls:
        skipped = len(unique_urls) - len(probeable_urls)
        skip_msg = f" (skipping {skipped} on unresolved hosts)" if skipped else ""
        print(f"Probing {len(probeable_urls)} URLs for authentication methods...{skip_msg}")
        path_probes, root_probes = asyncio.run(probe_urls_with_roots(
            probeable_urls,
            timeout=float(args.probe_timeout),
            max_concurrent=args.probe_concurrency,
            cookies=probe_cookies or None,
            headers=cli_headers or None,
        ))
        merge_probe_results(auth_map, path_probes)
        merge_root_probes(auth_map, root_probes)
        if root_probes:
            print(f"  probed {len(root_probes)} host root(s) to disclose undisclosed auth")

    if args.output:
        write_results(sources, args.output, auth_map, unresolved, ip_map)


if __name__ == "__main__":
    main()
