"""Tests for config_extractor.py"""

import asyncio
import json
import sys
import os
import threading
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from aiohttp import web

# Add parent directory to path so we can import the module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config_extractor import (
    _clean_url,
    _classify_url,
    _partition_urls,
    extract_urls,
    extract_urls_from_text,
    strip_js_block_comments,
    process_js_captures,
    sanitize_js_object,
    try_parse_json,
    _is_json_response,
    _exceeds_size_limit,
    process_network_captures,
    write_results,
    crawl,
    ConfigSource,
    AuthInfo,
    ProbeResult,
    AuthMethod,
    _host_root_url,
    _service_key,
    probe_urls,
    probe_urls_with_roots,
    merge_probe_results,
    merge_root_probes,
    _collapse_host_verdict,
    resolve_hosts,
    _parse_www_authenticate,
    _classify_probe,
    _cookies_from_kv,
    _headers_from_kv,
    _storage_state_to_probe_cookies,
    _check_auth_signal,
)


# ---------------------------------------------------------------------------
# Stub for Playwright Response objects
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, url="https://example.com", headers=None, status=200):
        self.url = url
        self.headers = headers or {}
        self.status = status


# ===========================================================================
# Part 1: Unit Tests — Pure Functions
# ===========================================================================


class TestCleanUrl:
    def test_no_trailing_punctuation(self):
        assert _clean_url("https://example.com/path") == "https://example.com/path"

    def test_trailing_period(self):
        assert _clean_url("https://example.com/path.") == "https://example.com/path"

    def test_trailing_comma(self):
        assert _clean_url("https://example.com/path,") == "https://example.com/path"

    def test_trailing_semicolon(self):
        assert _clean_url("https://example.com/path;") == "https://example.com/path"

    def test_trailing_colon(self):
        assert _clean_url("https://example.com/path:") == "https://example.com/path"

    def test_trailing_paren(self):
        assert _clean_url("https://example.com/path)") == "https://example.com/path"

    def test_trailing_backslash(self):
        assert _clean_url("https://example.com/path\\") == "https://example.com/path"


class TestClassifyUrl:
    def test_clean_url_returns_none(self):
        assert _classify_url("https://example.com/path") is None

    def test_template_flagged(self):
        assert _classify_url("https://${host}/path") == "template"

    def test_partial_template_flagged(self):
        assert _classify_url("https://${e") == "template"

    def test_backtick_flagged(self):
        assert _classify_url("https://example.com/`") == "template"

    def test_dollar_in_query_clean(self):
        # $ outside the hostname is fine — RFC 3986 sub-delim
        assert _classify_url("https://example.com/api?id=$1") is None

    def test_empty_host_flagged(self):
        assert _classify_url("http://") == "bad_host"

    def test_percent_in_host_flagged(self):
        assert _classify_url("https://www.%/path") == "bad_host"

    def test_underscore_in_host_flagged(self):
        # 'mock_section_url'-style placeholders
        assert _classify_url("https://mock_section_url/x") == "bad_host"

    def test_localhost_clean(self):
        assert _classify_url("http://localhost:8080/api") is None


class TestPartitionUrls:
    def test_split(self):
        clean, suspect = _partition_urls([
            "https://real.example.com/a",
            "https://${e}/b",
            "https://www.%/c",
            "https://other.example.com/d",
        ])
        assert clean == ["https://real.example.com/a", "https://other.example.com/d"]
        assert suspect == [
            ("https://${e}/b", "template"),
            ("https://www.%/c", "bad_host"),
        ]

    def test_all_clean(self):
        clean, suspect = _partition_urls(["https://a.example.com", "https://b.example.com"])
        assert len(clean) == 2 and suspect == []

    def test_all_suspect(self):
        clean, suspect = _partition_urls(["http://", "https://${x"])
        assert clean == []
        assert {r for _, r in suspect} == {"bad_host", "template"}


class TestExtractUrls:
    def test_string_with_url(self):
        result = extract_urls("https://api.example.com/v1")
        assert result == ["https://api.example.com/v1"]

    def test_string_without_url(self):
        assert extract_urls("just some text") == []

    def test_dict_with_urls(self):
        obj = {"api": "https://a.com", "cdn": "https://b.com"}
        result = extract_urls(obj)
        assert set(result) == {"https://a.com", "https://b.com"}

    def test_nested_dict(self):
        obj = {"outer": {"inner": "https://deep.com/api"}}
        result = extract_urls(obj)
        assert result == ["https://deep.com/api"]

    def test_list_of_strings(self):
        obj = ["https://a.com", "https://b.com"]
        result = extract_urls(obj)
        assert result == ["https://a.com", "https://b.com"]

    def test_mixed_nesting(self):
        obj = [{"urls": ["https://a.com"]}, "https://b.com"]
        result = extract_urls(obj)
        assert set(result) == {"https://a.com", "https://b.com"}

    def test_deduplication(self):
        obj = {"a": "https://dup.com", "b": "https://dup.com"}
        result = extract_urls(obj)
        assert result == ["https://dup.com"]

    def test_shared_seen_set(self):
        seen = set()
        r1 = extract_urls("https://shared.com", seen)
        r2 = extract_urls("https://shared.com", seen)
        assert r1 == ["https://shared.com"]
        assert r2 == []

    def test_integer_value_ignored(self):
        assert extract_urls(42) == []

    def test_none_value_ignored(self):
        assert extract_urls(None) == []


class TestExtractUrlsFromText:
    def test_single_url(self):
        result = extract_urls_from_text('config = "https://api.example.com"')
        assert result == ["https://api.example.com"]

    def test_multiple_urls(self):
        text = 'a: "https://a.com", b: "https://b.com", c: "http://c.com"'
        result = extract_urls_from_text(text)
        assert len(result) == 3

    def test_deduplication(self):
        text = "https://dup.com and https://dup.com again"
        result = extract_urls_from_text(text)
        assert result == ["https://dup.com"]

    def test_no_urls(self):
        assert extract_urls_from_text("nothing here") == []

    def test_url_with_query_string(self):
        text = "https://example.com/api?key=val&foo=bar"
        result = extract_urls_from_text(text)
        assert result == ["https://example.com/api?key=val&foo=bar"]


class TestStripJsBlockComments:
    def test_url_in_block_comment_removed(self):
        # The license-banner case that motivated this.
        text = '/*! bundled by webpack, https://reactjs.org */ var x = 1;'
        assert "https://reactjs.org" not in strip_js_block_comments(text)

    def test_multiline_license_banner_removed(self):
        text = (
            '/*!\n'
            '  * Bootstrap v5.3.7 (https://getbootstrap.com/)\n'
            '  * https://github.com/twbs/bootstrap/blob/main/LICENSE\n'
            '  */\n'
            'var api = "https://api.internal.corp/v1";'
        )
        out = strip_js_block_comments(text)
        assert "https://getbootstrap.com/" not in out
        assert "https://github.com/twbs/bootstrap/blob/main/LICENSE" not in out
        assert "https://api.internal.corp/v1" in out

    def test_url_in_string_kept(self):
        # The `//` in a real URL must never be read as a comment.
        text = 'var api = "https://api.internal.corp/v1";'
        assert "https://api.internal.corp/v1" in strip_js_block_comments(text)

    def test_double_slash_in_string_not_a_comment(self):
        text = "const u = 'http://a.corp/x'; const v = 'http://b.corp/y';"
        out = strip_js_block_comments(text)
        assert "http://a.corp/x" in out
        assert "http://b.corp/y" in out

    def test_block_comment_markers_in_string_kept(self):
        # `/*` and `*/` inside a string literal must not trigger comment stripping.
        text = 'var u = "https://real.corp/a/*b*/c";'
        assert "https://real.corp/a/*b*/c" in strip_js_block_comments(text)

    def test_url_next_to_slash_stripping_regex_survives(self):
        # A URL-normalizing regex with an escaped `//` sits in code; the real URL
        # that follows on the same (minified) line must survive. Block-only
        # stripping never touches `//`, so there's nothing to misfire.
        text = r'x.replace(/https?:\/\//g, "");var u="https://real.corp/api";'
        out = strip_js_block_comments(text)
        assert "https://real.corp/api" in out

    def test_line_comment_url_deliberately_kept(self):
        # `//` line comments are intentionally NOT stripped (see docstring);
        # stripping them safely needs regex disambiguation we don't attempt.
        text = 'var x = 1; // see https://docs.internal.corp/guide\n'
        assert "https://docs.internal.corp/guide" in strip_js_block_comments(text)

    def test_process_js_captures_ignores_banner_urls(self):
        body = (
            '/*! @license MIT https://cdn.jsdelivr.net/lib */\n'
            'var API = "https://api.internal.corp/v1";'
        )
        sources = process_js_captures([("https://app/bundle.js", body)])
        assert len(sources) == 1
        assert sources[0].urls_found == ["https://api.internal.corp/v1"]


class TestSanitizeJsObject:
    def test_line_comments(self):
        text = '{"a": 1 // comment\n}'
        result = json.loads(sanitize_js_object(text))
        assert result == {"a": 1}

    def test_block_comments(self):
        text = '{"a": 1 /* block comment */}'
        result = json.loads(sanitize_js_object(text))
        assert result == {"a": 1}

    def test_single_to_double_quotes(self):
        text = "{'a': 'b'}"
        result = json.loads(sanitize_js_object(text))
        assert result == {"a": "b"}

    def test_trailing_comma_object(self):
        text = '{"a": 1,}'
        result = json.loads(sanitize_js_object(text))
        assert result == {"a": 1}

    def test_trailing_comma_array(self):
        text = '[1, 2, 3,]'
        result = json.loads(sanitize_js_object(text))
        assert result == [1, 2, 3]

    def test_combined(self):
        text = "{'key': 'value', // comment\n}"
        result = json.loads(sanitize_js_object(text))
        assert result == {"key": "value"}


class TestTryParseJson:
    def test_valid_json(self):
        parsed, err = try_parse_json('{"key": "value"}')
        assert parsed == {"key": "value"}
        assert err is None

    def test_js_object(self):
        parsed, err = try_parse_json("{'key': 'value',}")
        assert parsed == {"key": "value"}
        assert err is None

    def test_unparseable(self):
        parsed, err = try_parse_json("not json at all")
        assert parsed is None
        assert err is not None


class TestProcessNetworkCaptures:
    def test_valid_json_with_urls(self):
        captured = [("https://cdn.com/config.json", '{"api": "https://api.com/v1"}')]
        result = process_network_captures(captured)
        assert len(result) == 1
        assert "https://api.com/v1" in result[0].urls_found
        assert result[0].error is None

    def test_invalid_json_fallback(self):
        captured = [("https://cdn.com/broken.json", 'api_url = "https://api.com/v1"')]
        result = process_network_captures(captured)
        assert len(result) == 1
        assert "https://api.com/v1" in result[0].urls_found

    def test_no_urls_skipped(self):
        captured = [("https://cdn.com/data.json", '{"count": 42}')]
        result = process_network_captures(captured)
        assert len(result) == 0

    def test_multiple_captures(self):
        captured = [
            ("https://a.com/config.json", '{"url": "https://a.com/api"}'),
            ("https://b.com/config.json", '{"url": "https://b.com/api"}'),
        ]
        result = process_network_captures(captured)
        assert len(result) == 2


# ===========================================================================
# Part 2: Unit Tests with Mocks — Response Helpers
# ===========================================================================


class TestIsJsonResponse:
    def test_json_content_type(self):
        resp = FakeResponse(headers={"content-type": "application/json"})
        assert _is_json_response(resp) is True

    def test_json_content_type_with_charset(self):
        resp = FakeResponse(headers={"content-type": "application/json; charset=utf-8"})
        assert _is_json_response(resp) is True

    def test_html_content_type(self):
        resp = FakeResponse(headers={"content-type": "text/html"})
        assert _is_json_response(resp) is False

    def test_json_url_extension(self):
        resp = FakeResponse(url="https://cdn.com/config.json")
        assert _is_json_response(resp) is True

    def test_json_url_with_query(self):
        resp = FakeResponse(url="https://cdn.com/config.json?v=2")
        assert _is_json_response(resp) is True

    def test_non_json(self):
        resp = FakeResponse(
            url="https://cdn.com/data.xml",
            headers={"content-type": "text/plain"},
        )
        assert _is_json_response(resp) is False


class TestExceedsSizeLimit:
    def test_under_limit(self):
        resp = FakeResponse(headers={"content-length": "1000"})
        assert _exceeds_size_limit(resp) is False

    def test_over_limit(self):
        resp = FakeResponse(headers={"content-length": "10000000"})
        assert _exceeds_size_limit(resp) is True

    def test_no_header(self):
        resp = FakeResponse(headers={})
        assert _exceeds_size_limit(resp) is False

    def test_non_numeric(self):
        resp = FakeResponse(headers={"content-length": "unknown"})
        assert _exceeds_size_limit(resp) is False


# ===========================================================================
# Part 3: Integration Tests — Local HTTP Server + Playwright
# ===========================================================================

INDEX_HTML = """\
<html>
<head>
  <script type="application/json">
    {"strategy_a_url": "https://strategy-a.example.com/api"}
  </script>
</head>
<body>
  <script>
    window.__CONFIG__ = {
      "cdnUrl": "https://strategy-b.example.com/cdn",
      "debug": false
    };
  </script>
  <script>
    fetch("/api/settings.json");
  </script>
  <a href="/deep">Deep page</a>
  <button id="load" type="button"
    onclick="fetch('/api/click-only.json')">Load extra config</button>
  <script>fetch("/protected/config.json").catch(function(){});</script>
</body>
</html>
"""

DEEP_HTML = """\
<html>
<head>
  <script type="application/json">
    {"deep_url": "https://deep-page.example.com/api"}
  </script>
</head>
<body>deep</body>
</html>
"""

CONFIG_JSON = json.dumps({"endpoint": "https://strategy-c.example.com/endpoint"})
SETTINGS_JSON = json.dumps({"dashboard": "https://network.example.com/dashboard"})
CLICK_ONLY_JSON = json.dumps({"click": "https://click-triggered.example.com/api"})
PROTECTED_CONFIG_JSON = json.dumps({"protected_url": "https://protected-api.example.com/v1"})

# Simulated lazy chunk (never loaded by the entry page) with a hardcoded URL
CHUNK_ADMIN_JS = (
    'var ADMIN_API="https://chunk-admin.example.com/api";'
    'console.log("admin chunk loaded");'
)
ASSET_MANIFEST_JSON = json.dumps({
    "files": {
        "main.js": "/static/js/main.abc123.js",
        "admin.chunk.js": "/static/js/chunk-admin.js",
    },
    "entrypoints": ["static/js/main.abc123.js"],
})


def _create_app():
    app = web.Application()

    async def handle_index(request):
        return web.Response(text=INDEX_HTML, content_type="text/html")

    async def handle_deep(request):
        return web.Response(text=DEEP_HTML, content_type="text/html")

    async def handle_config_json(request):
        return web.Response(text=CONFIG_JSON, content_type="application/json")

    async def handle_settings_json(request):
        return web.Response(text=SETTINGS_JSON, content_type="application/json")

    async def handle_click_only_json(request):
        return web.Response(text=CLICK_ONLY_JSON, content_type="application/json")

    async def handle_not_json(request):
        return web.Response(text="<html>not json</html>", content_type="text/html")

    async def handle_asset_manifest(request):
        return web.Response(text=ASSET_MANIFEST_JSON, content_type="application/json")

    async def handle_chunk_admin(request):
        return web.Response(text=CHUNK_ADMIN_JS, content_type="application/javascript")

    async def handle_spa_fallback_manifest(request):
        # Simulates an SPA that returns index.html (200) for any unknown path,
        # including manifest probe paths it doesn't actually serve.
        html = (
            '<html><body>'
            '<img src="/assets/img/spa-fallback-image.avif">'
            '</body></html>'
        )
        return web.Response(text=html, content_type="text/html")

    async def handle_protected_config(request):
        if request.cookies.get("session") == "abc":
            return web.Response(text=PROTECTED_CONFIG_JSON, content_type="application/json")
        return web.Response(status=401, text="Unauthorized")

    app.router.add_get("/", handle_index)
    app.router.add_get("/deep", handle_deep)
    app.router.add_get("/config.json", handle_config_json)
    app.router.add_get("/api/settings.json", handle_settings_json)
    app.router.add_get("/api/click-only.json", handle_click_only_json)
    app.router.add_get("/not-json", handle_not_json)
    app.router.add_get("/asset-manifest.json", handle_asset_manifest)
    # /manifest.json is in MANIFEST_PATHS; serve SPA fallback HTML here.
    app.router.add_get("/manifest.json", handle_spa_fallback_manifest)
    app.router.add_get("/static/js/chunk-admin.js", handle_chunk_admin)
    app.router.add_get("/protected/config.json", handle_protected_config)
    return app


def _start_server_in_thread():
    """Start the aiohttp server in a background thread, return (base_url, cleanup_fn)."""
    loop = asyncio.new_event_loop()
    app = _create_app()
    runner = web.AppRunner(app)
    started = threading.Event()
    port_holder = [0]

    def run():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, "127.0.0.1", 0)
        loop.run_until_complete(site.start())
        port_holder[0] = site._server.sockets[0].getsockname()[1]
        started.set()
        loop.run_forever()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    started.wait(timeout=10)

    base_url = f"http://127.0.0.1:{port_holder[0]}"

    def cleanup():
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=5)

    return base_url, cleanup


@pytest.fixture(scope="module")
def test_server():
    base_url, cleanup = _start_server_in_thread()
    yield base_url
    cleanup()


@pytest.mark.asyncio
async def test_full_crawl_finds_network_and_dom_sources(test_server):
    """Crawl the local test server and verify URLs from multiple strategies are found."""
    sources = await crawl(test_server, timeout=10000, wait_after_load=2000)

    all_urls = set()
    for src in sources:
        all_urls.update(src.urls_found)

    # Strategy A: <script type="application/json">
    assert "https://strategy-a.example.com/api" in all_urls

    # Strategy B: inline JS variable assignment
    assert "https://strategy-b.example.com/cdn" in all_urls

    # Network capture: /api/settings.json fetched by inline script
    assert "https://network.example.com/dashboard" in all_urls


@pytest.mark.asyncio
async def test_network_capture_skips_non_json(test_server):
    """Verify that non-JSON responses are not included in results."""
    sources = await crawl(test_server, timeout=10000, wait_after_load=2000)
    origins = [src.origin for src in sources]
    for origin in origins:
        assert "/not-json" not in origin


@pytest.mark.asyncio
async def test_output_file_writing(test_server, tmp_path):
    """Verify write_results produces valid JSON with expected structure."""
    sources = await crawl(test_server, timeout=10000, wait_after_load=2000)
    out_path = str(tmp_path / "results.json")
    write_results(sources, out_path)

    with open(out_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert isinstance(data, dict)
    assert "sources" in data
    assert "suspect_urls" in data
    assert isinstance(data["suspect_urls"], list)
    assert len(data["sources"]) > 0
    for entry in data["sources"]:
        assert "source" in entry
        assert "urls" in entry
        assert isinstance(entry["urls"], list)


def test_write_results_quarantines_suspect_urls(tmp_path):
    sources = [ConfigSource(
        origin="js: https://test/bundle.js",
        urls_found=[
            "https://real.example.com/api",
            "https://${env}/x",
            "https://www.%/y",
        ],
    )]
    out = tmp_path / "r.json"
    write_results(sources, str(out))
    with open(out, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["sources"][0]["urls"] == ["https://real.example.com/api"]
    assert {s["url"] for s in data["suspect_urls"]} == {
        "https://${env}/x", "https://www.%/y",
    }
    reasons = {s["url"]: s["reason"] for s in data["suspect_urls"]}
    assert reasons["https://${env}/x"] == "template"
    assert reasons["https://www.%/y"] == "bad_host"
    for s in data["suspect_urls"]:
        assert s["sources"] == ["js: https://test/bundle.js"]


def _auth_info(url, method, *, status=200, note=None, error=None):
    return AuthInfo(
        url=url,
        probe_result=ProbeResult(
            url=url, status_code=status, www_authenticate=None,
            detected_method=method, note=note, error=error,
        ),
    )


def test_write_results_services_map_collapses_and_filters(tmp_path):
    """The services map lists only services whose host resolved, collapses each
    service's per-URL verdicts by precedence (concrete scheme > none), flags
    disagreement with `mixed`, and counts probe transport errors as
    `unreachable`. Keys are origins; `ips` are joined through the hostname."""
    sources = [ConfigSource(
        origin="js: https://app/bundle.js",
        urls_found=[
            "https://svc.example.com/api",   # bearer
            "https://svc.example.com/",      # unauthenticated -> host is mixed
            "https://down.example.com/x",    # resolved but probe failed
            "https://dead.example.com/y",    # unresolved -> excluded
        ],
    )]
    auth_map = {
        "https://svc.example.com/api": _auth_info(
            "https://svc.example.com/api", AuthMethod.BEARER, status=401,
            note="challenged at /api"),
        "https://svc.example.com/": _auth_info(
            "https://svc.example.com/", AuthMethod.UNAUTHENTICATED),
        "https://down.example.com/x": _auth_info(
            "https://down.example.com/x", None, status=None,
            error="Cannot connect to host"),
    }
    unresolved = [{"host": "dead.example.com", "error": "NXDOMAIN"}]
    ip_map = {
        "svc.example.com": ["10.0.0.5"],
        "down.example.com": ["10.0.0.6", "10.0.0.7"],  # multiple A records
    }

    out = tmp_path / "r.json"
    write_results(sources, str(out), auth_map, unresolved, ip_map)
    with open(out, "r", encoding="utf-8") as f:
        data = json.load(f)

    services = data["services"]
    assert set(services) == {"https://svc.example.com", "https://down.example.com"}
    assert "https://dead.example.com" not in services  # excluded: failed DNS

    svc = services["https://svc.example.com"]
    assert svc["ips"] == ["10.0.0.5"]  # joined through the hostname
    assert svc["auth_verdict"] == "bearer"  # concrete scheme outranks none
    assert svc["status_codes"] == [200, 401]  # distinct, sorted
    # The evidence the scalars above were collapsed from: each URL's own verdict,
    # its note if it carried one, and null fields omitted entirely.
    assert svc["urls"] == {
        "https://svc.example.com/": {
            "status_code": 200, "detected_method": "unauthenticated"},
        "https://svc.example.com/api": {
            "status_code": 401, "detected_method": "bearer",
            "note": "challenged at /api"},
    }
    assert svc["mixed"] is True
    assert svc["urls_probed"] == 2
    assert svc["unreachable"] == 0

    down = services["https://down.example.com"]
    assert down["ips"] == ["10.0.0.6", "10.0.0.7"]  # multiple IPs preserved
    assert down["auth_verdict"] is None    # only a transport error, no verdict
    assert down["status_codes"] == []      # transport error carries no status
    # The error string survives the collapse — `unreachable` alone would not say
    # whether this host refused the connection, timed out, or failed TLS.
    assert down["urls"] == {
        "https://down.example.com/x": {"error": "Cannot connect to host"},
    }
    assert down["mixed"] is False
    assert down["urls_probed"] == 1
    assert down["unreachable"] == 1


def test_write_results_omits_services_map_without_resolution(tmp_path):
    """No DNS-resolution pass (unresolved is None) -> no `services` map, since
    'passed DNS resolution' is undefined."""
    sources = [ConfigSource(
        origin="js: https://app/bundle.js",
        urls_found=["https://svc.example.com/api"],
    )]
    out = tmp_path / "r.json"
    write_results(sources, str(out))
    with open(out, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "services" not in data


def test_write_results_keys_services_by_origin(tmp_path):
    """Two ports on one host are distinct services; http vs https are distinct;
    the scheme's default port collapses into the bare origin; and `ips` are
    shared across services on the same hostname."""
    sources = [ConfigSource(
        origin="js: https://app/bundle.js",
        urls_found=[
            "https://svc.example.com/api",        # https default (:443)
            "https://svc.example.com:443/admin",  # same service as above
            "https://svc.example.com:8080/x",     # distinct: non-default port
            "http://svc.example.com/y",            # distinct: different scheme
        ],
    )]
    auth_map = {
        "https://svc.example.com/api": _auth_info(
            "https://svc.example.com/api", AuthMethod.NEGOTIATE, status=401),
        "https://svc.example.com:443/admin": _auth_info(
            "https://svc.example.com:443/admin", AuthMethod.NEGOTIATE, status=401),
        "https://svc.example.com:8080/x": _auth_info(
            "https://svc.example.com:8080/x", AuthMethod.UNAUTHENTICATED),
        "http://svc.example.com/y": _auth_info(
            "http://svc.example.com/y", AuthMethod.BASIC, status=401),
    }
    unresolved: list[dict] = []
    ip_map = {"svc.example.com": ["10.0.0.5"]}

    out = tmp_path / "r.json"
    write_results(sources, str(out), auth_map, unresolved, ip_map)
    with open(out, "r", encoding="utf-8") as f:
        data = json.load(f)

    services = data["services"]
    assert set(services) == {
        "https://svc.example.com",        # :443 folded in with the default
        "https://svc.example.com:8080",
        "http://svc.example.com",
    }
    # The :443 URL collapsed into the bare https origin, not its own row.
    https_default = services["https://svc.example.com"]
    assert https_default["urls_probed"] == 2
    assert https_default["auth_verdict"] == "negotiate"
    assert https_default["mixed"] is False
    # Distinct port and distinct scheme keep their own verdicts.
    assert services["https://svc.example.com:8080"]["auth_verdict"] == "unauthenticated"
    assert services["http://svc.example.com"]["auth_verdict"] == "basic"
    # All three share the one hostname's resolved IPs.
    assert all(s["ips"] == ["10.0.0.5"] for s in services.values())


def test_write_results_services_list_their_urls(tmp_path):
    """Each service carries `urls`: every clean discovered URL on that origin,
    sorted. Origin-scoped like the rest of the entry, so a second port on the
    same box gets its own list rather than sharing one."""
    sources = [
        ConfigSource(
            origin="js: https://app/bundle.js",
            urls_found=[
                "https://svc.example.com/z-api",
                "https://svc.example.com:8443/admin",   # distinct service
                "https://dead.example.com/gone",        # unresolved -> no entry
                "https://svc.example.com/${env}/tpl",   # suspect -> not a URL
            ],
        ),
        ConfigSource(  # a second source referencing one of the same URLs
            origin="network: https://svc.example.com/config.json",
            urls_found=[
                "https://svc.example.com/a-api",
                "https://svc.example.com/z-api",
            ],
        ),
    ]
    auth_map = {u: _auth_info(u, AuthMethod.UNAUTHENTICATED) for u in (
        "https://svc.example.com/z-api",
        "https://svc.example.com/a-api",
        "https://svc.example.com:8443/admin",
    )}
    unresolved = [{"host": "dead.example.com", "error": "NXDOMAIN"}]
    ip_map = {"svc.example.com": ["10.0.0.5"]}

    out = tmp_path / "r.json"
    write_results(sources, str(out), auth_map, unresolved, ip_map)
    with open(out, "r", encoding="utf-8") as f:
        data = json.load(f)

    services = data["services"]
    # Sorted, deduped across sources, and the templated URL is quarantined out.
    assert list(services["https://svc.example.com"]["urls"]) == [
        "https://svc.example.com/a-api",
        "https://svc.example.com/z-api",
    ]
    # Each key carries that URL's own evidence, not just its name.
    assert services["https://svc.example.com"]["urls"][
        "https://svc.example.com/a-api"] == {
            "status_code": 200, "detected_method": "unauthenticated"}
    # The other port's URL didn't leak into the first service's list.
    assert list(services["https://svc.example.com:8443"]["urls"]) == [
        "https://svc.example.com:8443/admin",
    ]
    assert "https://dead.example.com" not in services


def test_write_results_services_urls_flag_synthesized_roots(tmp_path):
    """A host root probed on our own initiative is listed among the service's
    URLs — it is the evidence behind the verdict — but flagged `synthesized`, so
    the report never implies the config referenced `/`."""
    sources = [ConfigSource(
        origin="js: https://app/bundle.js",
        urls_found=["https://svc.example.com/api"],
    )]
    auth_map = {
        "https://svc.example.com/api": _auth_info(
            "https://svc.example.com/api", AuthMethod.UNKNOWN, status=401,
            note="auth required, scheme undisclosed; host root discloses ntlm"),
        "https://svc.example.com/": AuthInfo(
            url="https://svc.example.com/",
            probe_result=ProbeResult(
                url="https://svc.example.com/", status_code=401,
                www_authenticate="NTLM", detected_method=AuthMethod.NTLM),
            synthesized=True,
        ),
    }
    out = tmp_path / "r.json"
    write_results(sources, str(out), auth_map, [], {"svc.example.com": ["10.0.0.5"]})
    with open(out, "r", encoding="utf-8") as f:
        data = json.load(f)

    svc = data["services"]["https://svc.example.com"]
    assert svc["auth_verdict"] == "ntlm"       # the root's disclosure won
    assert svc["urls_probed"] == 2
    assert len(svc["urls"]) == 2               # and the counts reconcile
    # The root is present with the raw challenge that produced the verdict,
    # flagged as ours rather than the config's.
    assert svc["urls"]["https://svc.example.com/"] == {
        "synthesized": True, "status_code": 401,
        "www_authenticate": "NTLM", "detected_method": "ntlm",
    }
    # The referenced path keeps its own weaker verdict, unflagged.
    assert "synthesized" not in svc["urls"]["https://svc.example.com/api"]
    assert svc["urls"]["https://svc.example.com/api"]["detected_method"] == "unknown"
    assert "auth" not in data


@pytest.mark.asyncio
async def test_default_single_url_unchanged(test_server):
    """Without follow_links, the deep route and the cookie-gated API must NOT appear."""
    sources = await crawl(
        test_server,
        timeout=10000,
        wait_after_load=2000,
    )
    all_urls = {u for s in sources for u in s.urls_found}
    assert "https://deep-page.example.com/api" not in all_urls
    assert "https://protected-api.example.com/v1" not in all_urls


@pytest.mark.asyncio
async def test_manifest_probe_skips_spa_html_fallback(test_server):
    """SPA fallback (HTML body served at /manifest.json with 200) must not
    be captured as a manifest, and its embedded asset URLs must not surface."""
    sources = await crawl(
        test_server,
        timeout=10000,
        wait_after_load=2000,
    )
    for src in sources:
        assert "/manifest.json" not in src.origin
    all_urls = {u for s in sources for u in s.urls_found}
    spa_asset = f"{test_server}/assets/img/spa-fallback-image.avif"
    assert spa_asset not in all_urls


@pytest.mark.asyncio
async def test_manifest_probe_finds_lazy_chunk_url(test_server):
    """Manifest probe should fetch chunk-admin.js even though no page links to it."""
    sources = await crawl(
        test_server,
        timeout=10000,
        wait_after_load=2000,
    )
    all_urls = {u for s in sources for u in s.urls_found}
    assert "https://chunk-admin.example.com/api" in all_urls


@pytest.mark.asyncio
async def test_follow_links_finds_deep_route(test_server):
    """With follow_links=True the crawler should discover /deep and capture its config."""
    sources = await crawl(
        test_server,
        timeout=10000,
        wait_after_load=2000,
        follow_links=True,
        max_pages=3,
    )
    all_urls = {u for s in sources for u in s.urls_found}
    assert "https://deep-page.example.com/api" in all_urls


@pytest.mark.asyncio
async def test_interaction_triggers_xhr(test_server):
    """The click-only fetch should be captured (interactions always run)."""
    sources = await crawl(
        test_server,
        timeout=10000,
        wait_after_load=2000,
        interact_budget_ms=6000,
    )
    all_urls = {u for s in sources for u in s.urls_found}
    assert "https://click-triggered.example.com/api" in all_urls


# ===========================================================================
# Part 4: Auth Detection — Unit Tests
# ===========================================================================


class TestParseWwwAuthenticate:
    # Returns (method, note). Known schemes carry no note; an unrecognized but
    # well-formed scheme is OTHER with the scheme named; a tokenless header is
    # UNKNOWN. StrEnum members compare equal to their string value, so the
    # bare-string asserts below double as a check on that contract.
    def test_basic(self):
        assert _parse_www_authenticate('Basic realm="test"') == ("basic", None)

    def test_bearer(self):
        assert _parse_www_authenticate("Bearer") == ("bearer", None)

    def test_negotiate(self):
        assert _parse_www_authenticate("Negotiate") == ("negotiate", None)

    def test_other_scheme_is_named_in_note(self):
        # An uncommon scheme collapses to OTHER, but the specific name survives
        # in the note (and the raw header is kept on the ProbeResult).
        assert _parse_www_authenticate("Digest realm=x") == (
            "other", "challenge scheme: digest")

    def test_empty_is_malformed(self):
        assert _parse_www_authenticate("") == ("unknown", "malformed WWW-Authenticate")

    def test_whitespace_only_is_malformed(self):
        # Truthy but tokenless — the case the old `scheme or "unknown"` swallowed.
        assert _parse_www_authenticate("   ") == ("unknown", "malformed WWW-Authenticate")


class TestClassifyProbe:
    # _classify_probe returns (detected_method, note). detected_method is an
    # auth verdict only; note carries the inconclusive/heads-up context.
    def test_401_with_basic(self):
        assert _classify_probe(401, 'Basic realm="x"') == ("basic", None)

    def test_401_without_header(self):
        # Bare 401: auth required, but the scheme isn't disclosed.
        assert _classify_probe(401, None) == ("unknown", "auth required, scheme undisclosed")

    def test_403_with_bearer_challenge(self):
        # RFC 6750 insufficient_scope: 403 carries a Bearer challenge, which
        # must win over the opaque "forbidden" note.
        assert _classify_probe(403, 'Bearer error="insufficient_scope"') == ("bearer", None)

    def test_403_without_header(self):
        assert _classify_probe(403, None) == ("unknown", "forbidden (403)")

    def test_400_is_a_note(self):
        assert _classify_probe(400, None) == ("unknown", "bad request (400)")

    def test_404_is_a_note(self):
        assert _classify_probe(404, None) == ("unknown", "not found (404)")

    def test_407_proxy_auth_is_a_note(self):
        # A proxy in the path is a topology heads-up, not the service's method.
        assert _classify_probe(407, None) == ("unknown", "proxy authentication required (407)")

    def test_5xx_note_carries_reason_phrase(self):
        # The server's reason phrase rides along — 502/503/504 distinguish
        # proxy/upstream topology from a plain 500.
        assert _classify_probe(503, None, reason="Service Unavailable") == (
            "unknown", "server error: 503 Service Unavailable")

    def test_5xx_without_reason_phrase(self):
        assert _classify_probe(500, None) == ("unknown", "server error: 500")

    def test_200_with_header(self):
        # A challenge on any status is authoritative (RFC 7235 §4.1 MAY clause).
        assert _classify_probe(200, "Negotiate") == ("negotiate", None)

    def test_200_without_header(self):
        assert _classify_probe(200, None) == ("unauthenticated", None)

    def test_3xx_offhost_with_keyword_is_oauth(self):
        # Redirect off-host to an IdP whose URL carries an auth keyword:
        # federated SSO/OAuth, the strongest signal.
        assert _classify_probe(
            302, None,
            "https://login.microsoftonline.com/authorize?client_id=x",
            "https://app.example.com/api",
        ) == ("oauth", None)

    def test_3xx_samehost_with_keyword_is_login_redirect(self):
        # Same-origin redirect to a login path is local form auth, not OAuth.
        assert _classify_probe(
            302, None,
            "https://app.example.com/login",
            "https://app.example.com/dashboard",
        ) == ("login_redirect", None)

    def test_3xx_relative_location_with_keyword_is_login_redirect(self):
        # A relative "Location: /login" resolves to the same host once joined.
        assert _classify_probe(
            302, None, "/login", "https://app.example.com/dashboard",
        ) == ("login_redirect", None)

    def test_3xx_offhost_without_keyword_notes_off_origin(self):
        # Off-host redirect with no auth hint isn't an auth method, but the
        # cross-origin dependency is worth flagging in the note.
        assert _classify_probe(
            302, None,
            "https://cdn.othercorp.com/assets",
            "https://app.example.com/static",
        ) == ("unknown", "redirects off-origin to cdn.othercorp.com")

    def test_3xx_samehost_without_keyword_notes_redirect(self):
        method, note = _classify_probe(
            302, None,
            "https://app.example.com/new-path",
            "https://app.example.com/old-path",
        )
        assert method == "unknown"
        assert note == "redirects to https://app.example.com/new-path"
        assert "off-origin" not in note

    def test_3xx_relative_location_without_keyword_notes_redirect(self):
        assert _classify_probe(
            302, None, "/new-path", "https://app.example.com/old-path",
        ) == ("unknown", "redirects to https://app.example.com/new-path")

    def test_3xx_host_comparison_is_case_insensitive(self):
        # Differing host casing must not be mistaken for an off-host redirect.
        method, note = _classify_probe(
            302, None,
            "https://APP.example.com/new-path",
            "https://app.example.com/old-path",
        )
        assert method == "unknown"
        assert "off-origin" not in note

    def test_3xx_no_location_is_a_note(self):
        assert _classify_probe(302, None, "", "https://app.example.com/x") == (
            "unknown", "redirect (no Location header)")


# ===========================================================================
# Part 5: Auth Detection — Probing Integration Tests
# ===========================================================================

AUTH_CONFIG_JSON = json.dumps({
    "endpoint": "https://strategy-c.example.com/endpoint",
    "apiKey": "sk-test-key-12345",
})


def _create_auth_app(gated_root: bool = False):
    """Create test server with auth-aware routes.

    gated_root makes `/` answer a Basic challenge instead of serving the index,
    so a second instance on another port is a *distinguishable* service sharing
    one hostname — what the cross-origin breadcrumb test needs."""
    app = web.Application()

    async def handle_index(request):
        html = """\
<html>
<head>
  <script type="application/json">
    {"strategy_a_url": "https://strategy-a.example.com/api"}
  </script>
</head>
<body>
  <script>
    window.__CONFIG__ = {
      "cdnUrl": "https://strategy-b.example.com/cdn",
      "debug": false
    };
  </script>
  <script>
    fetch("/api/settings.json");
    fetch("/config.json");
  </script>
</body>
</html>
"""
        return web.Response(text=html, content_type="text/html")

    async def handle_config_json(request):
        return web.Response(text=AUTH_CONFIG_JSON, content_type="application/json")

    async def handle_settings_json(request):
        return web.Response(
            text=json.dumps({"dashboard": "https://network.example.com/dashboard"}),
            content_type="application/json",
        )

    async def handle_basic_auth(request):
        return web.Response(
            status=401,
            headers={"WWW-Authenticate": 'Basic realm="test"'},
            text="Unauthorized",
        )

    async def handle_bearer_auth(request):
        return web.Response(
            status=401,
            headers={"WWW-Authenticate": "Bearer"},
            text="Unauthorized",
        )

    async def handle_no_auth(request):
        return web.Response(text='{"ok": true}', content_type="application/json")

    async def handle_forbidden(request):
        return web.Response(status=403, text="Forbidden")

    async def handle_forbidden_bearer(request):
        # RFC 6750 insufficient_scope: valid token, missing scope -> 403 + challenge.
        return web.Response(
            status=403,
            headers={"WWW-Authenticate": 'Bearer error="insufficient_scope", scope="admin"'},
            text="Forbidden",
        )

    async def handle_bad_request(request):
        return web.Response(status=400, text="Bad Request")

    async def handle_not_found(request):
        return web.Response(status=404, text="Not Found")

    async def handle_redirect(request):
        return web.Response(status=301, headers={"Location": "/somewhere-else"})

    async def handle_redirect_to_login(request):
        return web.Response(status=302, headers={"Location": "/oauth/authorize?client_id=abc"})

    async def handle_redirect_to_idp(request):
        return web.Response(status=302, headers={
            "Location": "https://login.microsoftonline.com/authorize?client_id=abc"
        })

    async def handle_server_error(request):
        return web.Response(status=500, text="Internal Server Error")

    async def handle_bad_request_subpath(request):
        return web.Response(status=400, text="Bad Request — missing required params")

    async def handle_api_root(request):
        """Root of the /api-gated service returns 401 with Bearer."""
        return web.Response(
            status=401,
            headers={"WWW-Authenticate": "Bearer"},
            text="Unauthorized",
        )

    async def handle_gated_root(request):
        return web.Response(
            status=401,
            headers={"WWW-Authenticate": 'Basic realm="gated"'},
            text="Unauthorized",
        )

    # add_get registers HEAD too (allow_head defaults True), which is what the
    # root probe issues.
    app.router.add_get("/", handle_gated_root if gated_root else handle_index)
    app.router.add_get("/config.json", handle_config_json)
    app.router.add_get("/api/settings.json", handle_settings_json)
    app.router.add_get("/auth/basic", handle_basic_auth)
    app.router.add_get("/auth/bearer", handle_bearer_auth)
    app.router.add_get("/auth/none", handle_no_auth)
    app.router.add_get("/auth/forbidden", handle_forbidden)
    app.router.add_get("/auth/forbidden-bearer", handle_forbidden_bearer)
    app.router.add_get("/auth/bad-request", handle_bad_request)
    app.router.add_get("/auth/not-found", handle_not_found)
    app.router.add_get("/auth/redirect", handle_redirect)
    app.router.add_get("/auth/redirect-login", handle_redirect_to_login)
    app.router.add_get("/auth/redirect-idp", handle_redirect_to_idp)
    app.router.add_get("/auth/server-error", handle_server_error)
    app.router.add_get("/api-gated/v1/data", handle_bad_request_subpath)
    app.router.add_get("/api-gated/", handle_api_root)
    # Also handle HEAD requests
    app.router.add_route("HEAD", "/auth/basic", handle_basic_auth)
    app.router.add_route("HEAD", "/auth/bearer", handle_bearer_auth)
    app.router.add_route("HEAD", "/auth/none", handle_no_auth)
    app.router.add_route("HEAD", "/auth/forbidden", handle_forbidden)
    app.router.add_route("HEAD", "/auth/forbidden-bearer", handle_forbidden_bearer)
    app.router.add_route("HEAD", "/auth/bad-request", handle_bad_request)
    app.router.add_route("HEAD", "/auth/not-found", handle_not_found)
    app.router.add_route("HEAD", "/auth/redirect", handle_redirect)
    app.router.add_route("HEAD", "/auth/redirect-login", handle_redirect_to_login)
    app.router.add_route("HEAD", "/auth/redirect-idp", handle_redirect_to_idp)
    app.router.add_route("HEAD", "/auth/server-error", handle_server_error)
    app.router.add_route("HEAD", "/api-gated/v1/data", handle_bad_request_subpath)
    app.router.add_route("HEAD", "/api-gated/", handle_api_root)
    return app


def _start_auth_server(gated_root: bool = False):
    loop = asyncio.new_event_loop()
    app = _create_auth_app(gated_root=gated_root)
    runner = web.AppRunner(app)
    started = threading.Event()
    port_holder = [0]

    def run():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, "127.0.0.1", 0)
        loop.run_until_complete(site.start())
        port_holder[0] = site._server.sockets[0].getsockname()[1]
        started.set()
        loop.run_forever()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    started.wait(timeout=10)

    base_url = f"http://127.0.0.1:{port_holder[0]}"

    def cleanup():
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=5)

    return base_url, cleanup


@pytest.fixture(scope="module")
def auth_server():
    base_url, cleanup = _start_auth_server()
    yield base_url
    cleanup()


@pytest.fixture(scope="module")
def gated_auth_server():
    """A second server on another port — same hostname as `auth_server`, so the
    two are distinct origins on one box — whose root answers a Basic challenge."""
    base_url, cleanup = _start_auth_server(gated_root=True)
    yield base_url
    cleanup()


@pytest.mark.asyncio
async def test_probe_basic_auth(auth_server):
    results = await probe_urls([f"{auth_server}/auth/basic"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 401
    assert results[0].detected_method == "basic"
    assert results[0].www_authenticate is not None


@pytest.mark.asyncio
async def test_probe_bearer_auth(auth_server):
    results = await probe_urls([f"{auth_server}/auth/bearer"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 401
    assert results[0].detected_method == "bearer"


@pytest.mark.asyncio
async def test_probe_no_auth(auth_server):
    results = await probe_urls([f"{auth_server}/auth/none"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 200
    assert results[0].detected_method == "unauthenticated"


@pytest.mark.asyncio
async def test_probe_forbidden_keeps_verdict_and_probes_root(auth_server):
    """403 with no challenge keeps its own (unknown) verdict; the host root is
    probed separately and returned as an independent result, not substituted."""
    path_probes, root_probes = await probe_urls_with_roots(
        [f"{auth_server}/auth/forbidden"], timeout=5.0)
    assert len(path_probes) == 1
    assert path_probes[0].status_code == 403          # NOT overwritten by root
    assert path_probes[0].detected_method == "unknown"
    # root (/) returns 200 -> unauthenticated, kept as a separate synthesized probe
    assert len(root_probes) == 1
    assert root_probes[0].url == f"{auth_server}/"
    assert root_probes[0].status_code == 200
    assert root_probes[0].detected_method == "unauthenticated"
    # breadcrumb links the locked path to the open front door
    assert "host root is open" in path_probes[0].note


@pytest.mark.asyncio
async def test_breadcrumb_does_not_cross_origins(auth_server, gated_auth_server):
    """Two ports on one hostname are two services, each with its own front door.
    A gated path must get the breadcrumb from *its own* origin's root. Matching
    the roots by bare hostname let whichever root was probed last explain every
    gated path on the box — reporting an auth scheme for a service that was never
    probed that way, which is exactly the cross-origin merge _service_key exists
    to prevent in the report."""
    open_root = f"{auth_server}/auth/forbidden"          # this origin's / is 200
    gated_root = f"{gated_auth_server}/auth/forbidden"   # this origin's / is 401 Basic

    # Same host, different ports — indistinguishable to a hostname-keyed match.
    assert urlparse(open_root).hostname == urlparse(gated_root).hostname
    assert urlparse(open_root).port != urlparse(gated_root).port

    path_probes, root_probes = await probe_urls_with_roots(
        [open_root, gated_root], timeout=5.0)

    # Both front doors were probed, as two separate services.
    assert {r.url for r in root_probes} == {f"{auth_server}/", f"{gated_auth_server}/"}

    notes = {p.url: (p.note or "") for p in path_probes}
    assert "host root is open" in notes[open_root]
    assert "discloses basic" not in notes[open_root]        # the neighbour's verdict
    assert "host root discloses basic" in notes[gated_root]
    assert "is open" not in notes[gated_root]


@pytest.mark.asyncio
async def test_probe_forbidden_with_bearer_challenge(auth_server):
    """403 carrying a Bearer challenge (RFC 6750 insufficient_scope) must keep
    that challenge — the root fallback must NOT overwrite it with the host
    root's 200/unauthenticated."""
    results = await probe_urls([f"{auth_server}/auth/forbidden-bearer"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 403
    assert results[0].detected_method == "bearer"
    assert results[0].www_authenticate is not None


@pytest.mark.asyncio
async def test_probe_deduplicates_urls(auth_server):
    url = f"{auth_server}/auth/none"
    results = await probe_urls([url, url, url], timeout=5.0)
    assert len(results) == 1


@pytest.mark.asyncio
async def test_probe_unreachable_url():
    results = await probe_urls(["http://192.0.2.1:1/nonexistent"], timeout=1.0)
    assert len(results) == 1
    assert results[0].status_code is None
    assert results[0].error is not None


@pytest.mark.asyncio
async def test_probe_bad_request_probes_root_no_breadcrumb(auth_server):
    """400 (rejected before auth could be read) triggers a root probe so the
    host's front door is still mapped — but gets NO breadcrumb, since "host root
    discloses X" on a malformed-request path is an unfounded inference. The path
    keeps its own verdict."""
    path_probes, root_probes = await probe_urls_with_roots(
        [f"{auth_server}/auth/bad-request"], timeout=5.0)
    assert path_probes[0].status_code == 400
    assert path_probes[0].detected_method == "unknown"
    # root probed, front door learned as an independent fact
    # (/ is open -> unauthenticated)
    assert len(root_probes) == 1
    assert root_probes[0].url.endswith("/")
    assert root_probes[0].detected_method == "unauthenticated"
    # but no breadcrumb tying the 400 path to that root
    assert "host root" not in (path_probes[0].note or "")


@pytest.mark.asyncio
async def test_probe_not_found_no_root_probe(auth_server):
    """404 is a dead path -> no root probe, verdict kept."""
    path_probes, root_probes = await probe_urls_with_roots(
        [f"{auth_server}/auth/not-found"], timeout=5.0)
    assert path_probes[0].status_code == 404
    assert path_probes[0].detected_method == "unknown"
    assert root_probes == []


@pytest.mark.asyncio
async def test_probe_redirect(auth_server):
    results = await probe_urls([f"{auth_server}/auth/redirect"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 301
    # A plain same-host redirect with no auth hint isn't an auth method —
    # it's "unknown" with the target recorded in the note.
    assert results[0].detected_method == "unknown"
    assert "redirects to" in results[0].note


@pytest.mark.asyncio
async def test_probe_redirect_to_login(auth_server):
    # Relative, same-host redirect to a login path: local form auth.
    results = await probe_urls([f"{auth_server}/auth/redirect-login"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 302
    assert results[0].detected_method == "login_redirect"


@pytest.mark.asyncio
async def test_probe_redirect_to_idp(auth_server):
    # Off-host redirect to an external IdP: federated SSO/OAuth.
    results = await probe_urls([f"{auth_server}/auth/redirect-idp"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 302
    assert results[0].detected_method == "oauth"


@pytest.mark.asyncio
async def test_probe_server_error(auth_server):
    results = await probe_urls([f"{auth_server}/auth/server-error"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 500
    # 5xx is inconclusive for auth; the status (and reason phrase) ride in note.
    assert results[0].detected_method == "unknown"
    assert results[0].note is not None
    assert "server error: 500" in results[0].note


class TestHostRootUrl:
    def test_url_with_path(self):
        assert _host_root_url("https://api.example.com/v1/data") == "https://api.example.com/"

    def test_url_with_port(self):
        assert _host_root_url("http://localhost:8080/api/v1") == "http://localhost:8080/"

    def test_url_root_only(self):
        assert _host_root_url("https://api.example.com/") is None

    def test_url_no_path(self):
        assert _host_root_url("https://api.example.com") is None


class TestServiceKey:
    def test_strips_path_and_query(self):
        assert _service_key("https://h.example.com/v1/data?x=1") == "https://h.example.com"

    def test_default_https_port_stripped(self):
        # The bare origin and the explicit default port name one service.
        assert _service_key("https://h.example.com:443/x") == "https://h.example.com"

    def test_default_http_port_stripped(self):
        assert _service_key("http://h.example.com:80/x") == "http://h.example.com"

    def test_non_default_port_kept(self):
        assert _service_key("https://h.example.com:8080/x") == "https://h.example.com:8080"

    def test_scheme_distinguishes(self):
        assert _service_key("http://h.example.com/x") != _service_key("https://h.example.com/x")

    def test_host_lowercased(self):
        assert _service_key("https://H.Example.COM/x") == "https://h.example.com"

    def test_no_host_returns_none(self):
        assert _service_key("not-a-url") is None

    def test_out_of_range_port_treated_as_unspecified(self):
        # Accessing urlparse(...).port raises on a 99999 port; we swallow it.
        assert _service_key("http://h.example.com:99999/x") == "http://h.example.com"


@pytest.mark.asyncio
async def test_probe_subpath_400_probes_root_no_breadcrumb(auth_server):
    """A 400 on a deep path triggers a probe of the host root (not the path's own
    parent) so the front door is mapped; the path keeps its verdict and gets no
    breadcrumb."""
    path_probes, root_probes = await probe_urls_with_roots(
        [f"{auth_server}/api-gated/v1/data"], timeout=5.0)
    assert path_probes[0].status_code == 400
    assert path_probes[0].detected_method == "unknown"
    assert len(root_probes) == 1
    assert root_probes[0].url.endswith("/")
    assert "host root" not in (path_probes[0].note or "")


@pytest.mark.asyncio
async def test_probe_no_root_probe_when_root_only(auth_server):
    """When the URL is already the host root, there's no higher root to consult
    — _host_root_url returns None, so no root probe is synthesized."""
    assert _host_root_url(f"{auth_server}/") is None


def test_collapse_unknown_outranks_unauthenticated():
    """An open endpoint (often the host root) must never mask a locked-but-
    undisclosed sibling in the host headline; a concrete scheme still wins."""
    assert _collapse_host_verdict(
        {AuthMethod.UNKNOWN, AuthMethod.UNAUTHENTICATED}) == AuthMethod.UNKNOWN
    assert _collapse_host_verdict(
        {AuthMethod.BASIC, AuthMethod.UNKNOWN,
         AuthMethod.UNAUTHENTICATED}) == AuthMethod.BASIC


def test_collapse_ranks_by_blocker_risk():
    """The headline is the worst thing found across a service's URLs, not the
    most informative one: hard blockers (ntlm/basic/other) outrank the
    needs-review tier (negotiate), which outranks the exposable schemes."""
    # A blocker is never masked by a scheme that would pass exposure review.
    assert _collapse_host_verdict(
        {AuthMethod.NTLM, AuthMethod.NEGOTIATE}) == AuthMethod.NTLM
    assert _collapse_host_verdict(
        {AuthMethod.BASIC, AuthMethod.BEARER,
         AuthMethod.NEGOTIATE}) == AuthMethod.BASIC
    assert _collapse_host_verdict(
        {AuthMethod.OTHER, AuthMethod.BEARER}) == AuthMethod.OTHER
    # Needs-review outranks known-good, so an ambiguous negotiate isn't hidden
    # behind a bearer sibling.
    assert _collapse_host_verdict(
        {AuthMethod.NEGOTIATE, AuthMethod.BEARER,
         AuthMethod.LOGIN_REDIRECT}) == AuthMethod.NEGOTIATE
    # A concrete exposable verdict still beats the inconclusive catch-all, which
    # is dominated by 404s from stale config URLs.
    assert _collapse_host_verdict(
        {AuthMethod.BEARER, AuthMethod.UNKNOWN}) == AuthMethod.BEARER


def test_merge_root_probes_inserts_synthesized():
    """A probed root that no config referenced is inserted as a synthesized entry."""
    auth_map = {"https://h/x": AuthInfo(url="https://h/x")}
    root = ProbeResult(url="https://h/", status_code=200, www_authenticate=None,
                       detected_method=AuthMethod.UNAUTHENTICATED)
    merge_root_probes(auth_map, [root])
    assert auth_map["https://h/"].synthesized is True
    assert (auth_map["https://h/"].probe_result.detected_method
            == AuthMethod.UNAUTHENTICATED)


def test_merge_root_probes_keeps_discovered_root_unmarked():
    """A root the config already referenced is folded in WITHOUT the synthesized
    mark — it's a genuine discovered URL, not one we invented."""
    auth_map = {"https://h/": AuthInfo(url="https://h/")}  # discovered, unprobed
    root = ProbeResult(url="https://h/", status_code=401, www_authenticate="Basic",
                       detected_method=AuthMethod.BASIC)
    merge_root_probes(auth_map, [root])
    assert auth_map["https://h/"].synthesized is False
    assert auth_map["https://h/"].probe_result.detected_method == AuthMethod.BASIC


@pytest.mark.asyncio
async def test_write_results_with_auth(auth_server, tmp_path):
    """Probe evidence reaches the report under each service's `urls`."""
    sources = await crawl(auth_server, timeout=10000, wait_after_load=2000)
    all_urls = list({u for s in sources for u in s.urls_found})
    auth_map = {u: AuthInfo(url=u) for u in all_urls}
    probes = await probe_urls(all_urls, timeout=5.0)
    merge_probe_results(auth_map, probes)

    out_path = str(tmp_path / "results_auth.json")
    # unresolved=[] is the shape main() always passes: the DNS pass ran and every
    # host resolved. `services` is gated on that pass having happened.
    write_results(sources, out_path, auth_map, [], {})

    with open(out_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "auth" not in data          # folded away
    services = data["services"]
    assert services
    probed = {url: ev for svc in services.values()
              for url, ev in svc["urls"].items()}
    assert probed
    for url, evidence in probed.items():
        # Every probed URL reports either a verdict or why it couldn't be reached.
        assert "detected_method" in evidence or "error" in evidence


# ===========================================================================
# Part 6: Authenticated Sessions
# ===========================================================================


class TestCookiesFromKv:
    def test_basic_kv(self):
        cookies = _cookies_from_kv(["session=abc"], "https://app.example.com/")
        assert cookies == [{"name": "session", "value": "abc",
                            "domain": "app.example.com", "path": "/"}]

    def test_value_with_equals(self):
        cookies = _cookies_from_kv(["token=a=b=c"], "https://x.test/")
        assert cookies[0]["value"] == "a=b=c"

    def test_multiple(self):
        cookies = _cookies_from_kv(["a=1", "b=2"], "https://x.test/")
        assert {c["name"] for c in cookies} == {"a", "b"}

    def test_malformed_skipped(self):
        cookies = _cookies_from_kv(["bogus", "ok=yes"], "https://x.test/")
        assert len(cookies) == 1
        assert cookies[0]["name"] == "ok"


class TestHeadersFromKv:
    def test_basic(self):
        h = _headers_from_kv(["Authorization: Bearer xyz"])
        assert h == {"Authorization": "Bearer xyz"}

    def test_value_with_colon(self):
        h = _headers_from_kv(["X-Trace: abc:def:ghi"])
        assert h["X-Trace"] == "abc:def:ghi"

    def test_malformed_skipped(self):
        h = _headers_from_kv(["bogus", "Ok: yes"])
        assert h == {"Ok": "yes"}


class TestStorageStateToProbeCookies:
    def test_extracts_matching_host(self, tmp_path):
        path = tmp_path / "auth.json"
        path.write_text(json.dumps({
            "cookies": [
                {"name": "session", "value": "abc", "domain": "127.0.0.1"},
                {"name": "other", "value": "xyz", "domain": "other.example.com"},
            ],
            "origins": [],
        }))
        cookies = _storage_state_to_probe_cookies(str(path), "http://127.0.0.1:8080/")
        assert cookies == {"session": "abc"}

    def test_missing_file_returns_empty(self, tmp_path):
        cookies = _storage_state_to_probe_cookies(str(tmp_path / "nope.json"),
                                                  "https://app.example.com/")
        assert cookies == {}

    def test_dotted_domain_matches_subdomain(self, tmp_path):
        path = tmp_path / "auth.json"
        path.write_text(json.dumps({
            "cookies": [{"name": "s", "value": "1", "domain": ".example.com"}],
            "origins": [],
        }))
        cookies = _storage_state_to_probe_cookies(str(path), "https://app.example.com/")
        assert cookies == {"s": "1"}


class TestCheckAuthSignal:
    def test_clean_returns_none(self):
        assert _check_auth_signal("https://app.example.com/",
                                  "https://app.example.com/", 200, None) is None

    def test_401_signal(self):
        msg = _check_auth_signal("https://app.example.com/",
                                 "https://app.example.com/", 401, None)
        assert msg and "401" in msg

    def test_www_authenticate_signal(self):
        msg = _check_auth_signal("https://app.example.com/",
                                 "https://app.example.com/", 200, "Bearer")
        assert msg and "Bearer" in msg

    def test_off_origin_redirect(self):
        msg = _check_auth_signal("https://app.example.com/",
                                 "https://idp.example.com/login", 200, None)
        assert msg and "idp.example.com" in msg

    def test_login_url_pattern(self):
        msg = _check_auth_signal("https://app.example.com/",
                                 "https://app.example.com/login", 200, None)
        assert msg and "login" in msg


@pytest.mark.asyncio
async def test_crawl_with_cookie_finds_protected_config(test_server):
    """With session cookie set on the context, the protected URL is captured."""
    host = test_server.replace("http://", "").split(":")[0]
    sources = await crawl(
        test_server,
        timeout=10000,
        wait_after_load=2000,
        cookies=[{"name": "session", "value": "abc", "domain": host, "path": "/"}],
    )
    all_urls = {u for s in sources for u in s.urls_found}
    assert "https://protected-api.example.com/v1" in all_urls


@pytest.mark.asyncio
async def test_crawl_without_cookie_misses_protected_config(test_server):
    """Without the session cookie, the protected URL must not appear."""
    sources = await crawl(test_server, timeout=10000, wait_after_load=2000)
    all_urls = {u for s in sources for u in s.urls_found}
    assert "https://protected-api.example.com/v1" not in all_urls


@pytest.mark.asyncio
async def test_storage_state_roundtrip(test_server, tmp_path):
    """A Playwright storage-state JSON file with the right cookie should unlock the route."""
    host = test_server.replace("http://", "").split(":")[0]
    state_path = tmp_path / "auth.json"
    state_path.write_text(json.dumps({
        "cookies": [{
            "name": "session", "value": "abc",
            "domain": host, "path": "/",
            "expires": -1, "httpOnly": False,
            "secure": False, "sameSite": "Lax",
        }],
        "origins": [],
    }))
    sources = await crawl(
        test_server,
        timeout=10000,
        wait_after_load=2000,
        storage_state=str(state_path),
    )
    all_urls = {u for s in sources for u in s.urls_found}
    assert "https://protected-api.example.com/v1" in all_urls


@pytest.mark.asyncio
async def test_probe_urls_with_cookie(test_server):
    """probe_urls should send cookies and see 200 instead of 401."""
    url = f"{test_server}/protected/config.json"

    no_cookie = await probe_urls([url], timeout=5.0)
    assert no_cookie[0].status_code == 401

    with_cookie = await probe_urls([url], timeout=5.0, cookies={"session": "abc"})
    assert with_cookie[0].status_code == 200


@pytest.mark.asyncio
async def test_probe_urls_with_extra_header(test_server):
    """Extra headers passed to probe_urls should be merged with the User-Agent."""
    # /config.json doesn't gate on headers, but we verify the call shape works.
    url = f"{test_server}/config.json"
    results = await probe_urls([url], timeout=5.0,
                               headers={"X-Custom": "test"})
    assert results[0].status_code == 200


# ===========================================================================
# Part 7: DNS resolution
# ===========================================================================

# The .invalid TLD (RFC 6761) is reserved and guaranteed never to resolve.
_BAD_HOST = "doesnotexist.invalid"


@pytest.mark.asyncio
async def test_resolve_hosts_returns_empty_for_resolvable():
    failures, ip_map = await resolve_hosts(["localhost"])
    assert failures == []
    # A resolvable host is captured in ip_map with its address(es).
    assert ip_map["localhost"]
    assert all(isinstance(ip, str) for ip in ip_map["localhost"])


@pytest.mark.asyncio
async def test_resolve_hosts_reports_nxdomain():
    failures, ip_map = await resolve_hosts([_BAD_HOST])
    assert len(failures) == 1
    assert failures[0]["host"] == _BAD_HOST
    assert failures[0]["error"] == "NXDOMAIN"
    assert _BAD_HOST not in ip_map  # a failed host yields no IPs


@pytest.mark.asyncio
async def test_resolve_hosts_mixed():
    failures, ip_map = await resolve_hosts(["localhost", _BAD_HOST])
    assert {entry["host"] for entry in failures} == {_BAD_HOST}
    assert ip_map.get("localhost")  # resolved
    assert _BAD_HOST not in ip_map  # failed


@pytest.mark.asyncio
async def test_resolve_hosts_dedupes():
    failures, _ = await resolve_hosts([_BAD_HOST, _BAD_HOST, _BAD_HOST])
    assert len(failures) == 1


def test_write_results_includes_unresolved_hosts(tmp_path):
    sources = [ConfigSource(
        origin="js: https://test/bundle.js",
        urls_found=["https://real.example.com/api"],
    )]
    out = tmp_path / "r.json"
    unresolved = [{"host": "x.invalid", "error": "NXDOMAIN"}]
    write_results(sources, str(out), unresolved=unresolved)
    with open(out, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["unresolved_hosts"] == unresolved


def test_write_results_omits_unresolved_when_none(tmp_path):
    sources = [ConfigSource(
        origin="js: https://test/bundle.js",
        urls_found=["https://real.example.com/api"],
    )]
    out = tmp_path / "r.json"
    write_results(sources, str(out))
    with open(out, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "unresolved_hosts" not in data


@pytest.mark.asyncio
async def test_probe_filtering_skips_unresolved_hosts(test_server):
    """End-to-end: URLs on unresolved hosts must be excluded from probe input
    and from the auth map (they're reported via the unresolved list instead)."""
    from urllib.parse import urlparse

    good_url = f"{test_server}/config.json"
    bad_url = f"https://{_BAD_HOST}/api"
    unique_urls = [good_url, bad_url]

    # Replicate the main() flow: resolve, filter, probe, then check auth_map.
    auth_map = {u: AuthInfo(url=u) for u in unique_urls}
    hosts = sorted({urlparse(u).hostname for u in unique_urls if urlparse(u).hostname})
    unresolved, _ = await resolve_hosts(hosts)
    unresolved_set = {entry["host"] for entry in unresolved}

    assert _BAD_HOST in unresolved_set
    assert "127.0.0.1" not in unresolved_set

    probeable = [u for u in unique_urls if urlparse(u).hostname not in unresolved_set]
    for url in unique_urls:
        if urlparse(url).hostname in unresolved_set:
            del auth_map[url]

    assert probeable == [good_url]

    probes = await probe_urls(probeable, timeout=5.0)
    merge_probe_results(auth_map, probes)

    assert bad_url not in auth_map
    assert auth_map[good_url].probe_result is not None
    assert auth_map[good_url].probe_result.status_code == 200
