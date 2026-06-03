"""Tests for config_extractor.py"""

import asyncio
import json
import sys
import os
import threading

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
    _host_root_url,
    probe_urls,
    merge_probe_results,
    reconcile_auth,
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
    assert "unique_hosts" in data
    assert "suspect_urls" in data
    assert isinstance(data["unique_hosts"], list)
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
    assert data["unique_hosts"] == ["real.example.com"]
    assert {s["url"] for s in data["suspect_urls"]} == {
        "https://${env}/x", "https://www.%/y",
    }
    reasons = {s["url"]: s["reason"] for s in data["suspect_urls"]}
    assert reasons["https://${env}/x"] == "template"
    assert reasons["https://www.%/y"] == "bad_host"
    for s in data["suspect_urls"]:
        assert s["sources"] == ["js: https://test/bundle.js"]


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
    def test_basic(self):
        assert _parse_www_authenticate('Basic realm="test"') == "basic"

    def test_bearer(self):
        assert _parse_www_authenticate("Bearer") == "bearer"

    def test_negotiate(self):
        assert _parse_www_authenticate("Negotiate") == "negotiate"

    def test_unknown_scheme(self):
        assert _parse_www_authenticate("CustomScheme") == "customscheme"

    def test_empty(self):
        assert _parse_www_authenticate("") == "unknown"


class TestClassifyProbe:
    def test_401_with_basic(self):
        assert _classify_probe(401, 'Basic realm="x"') == "basic"

    def test_401_without_header(self):
        assert _classify_probe(401, None) == "unknown"

    def test_403_with_bearer_challenge(self):
        # RFC 6750 insufficient_scope: 403 carries a Bearer challenge, which
        # must win over the opaque "forbidden" classification.
        assert _classify_probe(403, 'Bearer error="insufficient_scope"') == "bearer"

    def test_403_without_header(self):
        assert _classify_probe(403, None) == "forbidden"

    def test_200_with_header(self):
        # A challenge on any status is authoritative (RFC 7235 §4.1 MAY clause).
        assert _classify_probe(200, "Negotiate") == "negotiate"

    def test_200_without_header(self):
        assert _classify_probe(200, None) == "none"


class TestReconcileAuth:
    def test_probe_www_authenticate_wins(self):
        auth_map = {
            "https://api.example.com": AuthInfo(
                url="https://api.example.com",
                probe_result=ProbeResult(
                    url="https://api.example.com",
                    status_code=401,
                    www_authenticate="Bearer",
                    detected_method="bearer",
                ),
            ),
        }
        reconcile_auth(auth_map)
        assert auth_map["https://api.example.com"].best_guess == "bearer"

    def test_probe_200_means_no_auth(self):
        auth_map = {
            "https://cdn.example.com": AuthInfo(
                url="https://cdn.example.com",
                probe_result=ProbeResult(
                    url="https://cdn.example.com",
                    status_code=200,
                    www_authenticate=None,
                    detected_method="none",
                ),
            ),
        }
        reconcile_auth(auth_map)
        assert auth_map["https://cdn.example.com"].best_guess == "none"

    def test_no_info_stays_unknown(self):
        auth_map = {
            "https://api.example.com": AuthInfo(url="https://api.example.com"),
        }
        reconcile_auth(auth_map)
        assert auth_map["https://api.example.com"].best_guess == "unknown"

    def test_forbidden(self):
        auth_map = {
            "https://api.example.com": AuthInfo(
                url="https://api.example.com",
                probe_result=ProbeResult(
                    url="https://api.example.com",
                    status_code=403,
                    www_authenticate=None,
                    detected_method="forbidden",
                ),
            ),
        }
        reconcile_auth(auth_map)
        assert auth_map["https://api.example.com"].best_guess == "forbidden"


# ===========================================================================
# Part 5: Auth Detection — Probing Integration Tests
# ===========================================================================

AUTH_CONFIG_JSON = json.dumps({
    "endpoint": "https://strategy-c.example.com/endpoint",
    "apiKey": "sk-test-key-12345",
})


def _create_auth_app():
    """Create test server with auth-aware routes."""
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

    app.router.add_get("/", handle_index)
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
    app.router.add_route("HEAD", "/auth/server-error", handle_server_error)
    app.router.add_route("HEAD", "/api-gated/v1/data", handle_bad_request_subpath)
    app.router.add_route("HEAD", "/api-gated/", handle_api_root)
    return app


def _start_auth_server():
    loop = asyncio.new_event_loop()
    app = _create_auth_app()
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
    assert results[0].detected_method == "none"


@pytest.mark.asyncio
async def test_probe_forbidden_with_fallback(auth_server):
    """403 on a path triggers host-root fallback; root (/) returns 200 → none."""
    results = await probe_urls([f"{auth_server}/auth/forbidden"], timeout=5.0)
    assert len(results) == 1
    # Fallback to host root which returns 200
    assert results[0].status_code == 200
    assert results[0].detected_method == "none"


@pytest.mark.asyncio
async def test_probe_forbidden_with_bearer_challenge(auth_server):
    """403 carrying a Bearer challenge (RFC 6750 insufficient_scope) must keep
    that challenge — the root fallback must NOT overwrite it with the host
    root's 200/none."""
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
async def test_probe_bad_request_with_fallback(auth_server):
    """400 on a path triggers host-root fallback; root (/) returns 200 → none."""
    results = await probe_urls([f"{auth_server}/auth/bad-request"], timeout=5.0)
    assert len(results) == 1
    # Fallback to host root which returns 200
    assert results[0].status_code == 200
    assert results[0].detected_method == "none"


@pytest.mark.asyncio
async def test_probe_not_found_with_fallback(auth_server):
    """404 on a path triggers host-root fallback; root (/) returns 200 → none."""
    results = await probe_urls([f"{auth_server}/auth/not-found"], timeout=5.0)
    assert len(results) == 1
    # Fallback to host root which returns 200
    assert results[0].status_code == 200
    assert results[0].detected_method == "none"


@pytest.mark.asyncio
async def test_probe_redirect(auth_server):
    results = await probe_urls([f"{auth_server}/auth/redirect"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 301
    assert results[0].detected_method == "redirect"


@pytest.mark.asyncio
async def test_probe_redirect_to_login(auth_server):
    results = await probe_urls([f"{auth_server}/auth/redirect-login"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 302
    assert results[0].detected_method == "oauth"


@pytest.mark.asyncio
async def test_probe_server_error(auth_server):
    results = await probe_urls([f"{auth_server}/auth/server-error"], timeout=5.0)
    assert len(results) == 1
    assert results[0].status_code == 500
    assert results[0].detected_method == "server_error"


class TestHostRootUrl:
    def test_url_with_path(self):
        assert _host_root_url("https://api.example.com/v1/data") == "https://api.example.com/"

    def test_url_with_port(self):
        assert _host_root_url("http://localhost:8080/api/v1") == "http://localhost:8080/"

    def test_url_root_only(self):
        assert _host_root_url("https://api.example.com/") is None

    def test_url_no_path(self):
        assert _host_root_url("https://api.example.com") is None


@pytest.mark.asyncio
async def test_probe_bad_request_falls_back_to_host_root(auth_server):
    """When a path returns 400, probe should retry at host root and use that result."""
    results = await probe_urls([f"{auth_server}/api-gated/v1/data"], timeout=5.0)
    assert len(results) == 1
    # The path returns 400, but the root fallback hits /api-gated/ which isn't
    # the host root — it falls back to host root (/) which serves HTML (200).
    # Since the host root returns 200, that's more informative than 400.
    # The result should NOT be "bad_request" since fallback found something better.
    assert results[0].detected_method != "bad_request"


@pytest.mark.asyncio
async def test_probe_bad_request_no_fallback_when_root_only(auth_server):
    """When URL is already at root, no fallback occurs — stays bad_request."""
    # Probe just the host root directly — _host_root_url returns None for root URLs
    # so we need a URL that returns 400 and has no useful root fallback.
    # We simulate this by testing _host_root_url returns None for the root.
    assert _host_root_url(f"{auth_server}/") is None


@pytest.mark.asyncio
async def test_write_results_with_auth(auth_server, tmp_path):
    """Verify write_results includes auth section when auth_map is provided."""
    sources = await crawl(auth_server, timeout=10000, wait_after_load=2000)
    all_urls = list({u for s in sources for u in s.urls_found})
    auth_map = {u: AuthInfo(url=u) for u in all_urls}
    probes = await probe_urls(all_urls, timeout=5.0)
    merge_probe_results(auth_map, probes)
    reconcile_auth(auth_map)

    out_path = str(tmp_path / "results_auth.json")
    write_results(sources, out_path, auth_map)

    with open(out_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "auth" in data
    assert isinstance(data["auth"], dict)
    for url, auth_entry in data["auth"].items():
        assert "best_guess" in auth_entry


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
    result = await resolve_hosts(["localhost"])
    assert result == []


@pytest.mark.asyncio
async def test_resolve_hosts_reports_nxdomain():
    result = await resolve_hosts([_BAD_HOST])
    assert len(result) == 1
    assert result[0]["host"] == _BAD_HOST
    assert result[0]["error"] == "NXDOMAIN"


@pytest.mark.asyncio
async def test_resolve_hosts_mixed():
    result = await resolve_hosts(["localhost", _BAD_HOST])
    hosts = {entry["host"] for entry in result}
    assert hosts == {_BAD_HOST}


@pytest.mark.asyncio
async def test_resolve_hosts_dedupes():
    result = await resolve_hosts([_BAD_HOST, _BAD_HOST, _BAD_HOST])
    assert len(result) == 1


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
    and marked 'unknown (unresolved host)' in the auth map."""
    from urllib.parse import urlparse

    good_url = f"{test_server}/config.json"
    bad_url = f"https://{_BAD_HOST}/api"
    unique_urls = [good_url, bad_url]

    # Replicate the main() flow: resolve, filter, probe, then check auth_map.
    auth_map = {u: AuthInfo(url=u) for u in unique_urls}
    hosts = sorted({urlparse(u).hostname for u in unique_urls if urlparse(u).hostname})
    unresolved = await resolve_hosts(hosts)
    unresolved_set = {entry["host"] for entry in unresolved}

    assert _BAD_HOST in unresolved_set
    assert "127.0.0.1" not in unresolved_set

    probeable = [u for u in unique_urls if urlparse(u).hostname not in unresolved_set]
    for url in unique_urls:
        if urlparse(url).hostname in unresolved_set:
            auth_map[url].best_guess = "unknown (unresolved host)"

    assert probeable == [good_url]

    probes = await probe_urls(probeable, timeout=5.0)
    merge_probe_results(auth_map, probes)
    reconcile_auth(auth_map)

    assert auth_map[bad_url].best_guess == "unknown (unresolved host)"
    assert auth_map[bad_url].probe_result is None
    assert auth_map[good_url].probe_result is not None
    assert auth_map[good_url].probe_result.status_code == 200
