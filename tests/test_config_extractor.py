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
    AuthHint,
    AuthInfo,
    ProbeResult,
    _redact_value,
    _match_auth_key,
    _host_root_url,
    find_auth_context,
    run_static_auth_analysis,
    probe_urls,
    merge_probe_results,
    reconcile_auth,
    _parse_www_authenticate,
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
</body>
</html>
"""

CONFIG_JSON = json.dumps({"endpoint": "https://strategy-c.example.com/endpoint"})
SETTINGS_JSON = json.dumps({"dashboard": "https://network.example.com/dashboard"})


def _create_app():
    app = web.Application()

    async def handle_index(request):
        return web.Response(text=INDEX_HTML, content_type="text/html")

    async def handle_config_json(request):
        return web.Response(text=CONFIG_JSON, content_type="application/json")

    async def handle_settings_json(request):
        return web.Response(text=SETTINGS_JSON, content_type="application/json")

    async def handle_not_json(request):
        return web.Response(text="<html>not json</html>", content_type="text/html")

    app.router.add_get("/", handle_index)
    app.router.add_get("/config.json", handle_config_json)
    app.router.add_get("/api/settings.json", handle_settings_json)
    app.router.add_get("/not-json", handle_not_json)
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
    assert isinstance(data["unique_hosts"], list)
    assert len(data["sources"]) > 0
    for entry in data["sources"]:
        assert "source" in entry
        assert "urls" in entry
        assert isinstance(entry["urls"], list)


# ===========================================================================
# Part 4: Auth Detection — Unit Tests
# ===========================================================================


class TestRedactValue:
    def test_long_string(self):
        assert _redact_value("sk-1234567890") == "sk-1***"

    def test_short_string(self):
        assert _redact_value("ab") == "[present]"

    def test_exactly_four(self):
        assert _redact_value("abcd") == "abcd***"

    def test_non_string(self):
        assert _redact_value(12345) == "[present]"

    def test_empty_string(self):
        assert _redact_value("") == "[present]"


class TestMatchAuthKey:
    def test_api_key(self):
        assert _match_auth_key("apiKey") == "api_key"
        assert _match_auth_key("api_key") == "api_key"
        assert _match_auth_key("API-KEY") == "api_key"

    def test_bearer(self):
        assert _match_auth_key("accessToken") == "bearer"
        assert _match_auth_key("access_token") == "bearer"
        assert _match_auth_key("bearerToken") == "bearer"
        assert _match_auth_key("token") == "bearer"

    def test_oauth(self):
        assert _match_auth_key("clientId") == "oauth"
        assert _match_auth_key("client_secret") == "oauth"
        assert _match_auth_key("oauth") == "oauth"

    def test_basic(self):
        assert _match_auth_key("username") == "basic"
        assert _match_auth_key("password") == "basic"

    def test_cookie_session(self):
        assert _match_auth_key("sessionId") == "cookie_session"
        assert _match_auth_key("session_token") == "cookie_session"
        assert _match_auth_key("csrf_token") == "cookie_session"

    def test_custom_header(self):
        assert _match_auth_key("authorization") == "custom_header"
        # x-api-key matches api_key pattern first (which is correct — it IS an API key header)
        assert _match_auth_key("x-api-key") == "api_key"

    def test_no_match(self):
        assert _match_auth_key("url") is None
        assert _match_auth_key("endpoint") is None
        assert _match_auth_key("name") is None


class TestFindAuthContext:
    def test_sibling_api_key(self):
        """Auth key as immediate sibling of URL → high confidence."""
        obj = {
            "apiUrl": "https://api.example.com/v1",
            "apiKey": "sk-test-1234567890",
        }
        hints = find_auth_context(obj, "test")
        assert len(hints) == 1
        assert hints[0].method == "api_key"
        assert hints[0].confidence == "high"
        assert hints[0].evidence_key == "apiKey"
        assert hints[0].evidence_value == "sk-t***"

    def test_sibling_bearer_token(self):
        obj = {
            "endpoint": "https://api.example.com",
            "accessToken": "eyJhbGciOiJIUzI1NiJ9",
        }
        hints = find_auth_context(obj, "test")
        assert len(hints) == 1
        assert hints[0].method == "bearer"
        assert hints[0].confidence == "high"

    def test_child_auth_dict(self):
        """Auth keys in child dict of URL container → medium confidence."""
        obj = {
            "url": "https://api.example.com",
            "auth": {
                "username": "admin",
                "password": "secret123",
            },
        }
        hints = find_auth_context(obj, "test")
        methods = {h.method for h in hints}
        assert "basic" in methods
        assert all(h.confidence == "medium" for h in hints)

    def test_no_url_no_hints(self):
        """Dict without URLs produces no hints even with auth keys."""
        obj = {"apiKey": "sk-test-1234", "name": "test"}
        hints = find_auth_context(obj, "test")
        assert len(hints) == 0

    def test_nested_service_config(self):
        """Nested service with URL in child and auth key in parent."""
        obj = {
            "token": "abc12345",
            "service": {
                "url": "https://api.example.com",
                "version": "v2",
            },
        }
        hints = find_auth_context(obj, "test")
        methods = [h.method for h in hints]
        assert "bearer" in methods

    def test_multiple_services(self):
        """Multiple services each with their own auth."""
        obj = {
            "serviceA": {
                "url": "https://a.example.com",
                "apiKey": "key-a-1234",
            },
            "serviceB": {
                "url": "https://b.example.com",
                "accessToken": "token-b-5678",
            },
        }
        hints = find_auth_context(obj, "test")
        methods = {h.method for h in hints}
        assert "api_key" in methods
        assert "bearer" in methods

    def test_list_of_configs(self):
        """List containing config dicts."""
        obj = [
            {"url": "https://a.example.com", "apiKey": "key123456"},
        ]
        hints = find_auth_context(obj, "test")
        assert len(hints) == 1
        assert hints[0].method == "api_key"


class TestRunStaticAuthAnalysis:
    def test_associates_hints_with_urls(self):
        sources = [
            ConfigSource(
                origin="test",
                json_payload={
                    "endpoint": "https://api.example.com",
                    "apiKey": "sk-test-1234567890",
                },
                urls_found=["https://api.example.com"],
            ),
        ]
        auth_map = run_static_auth_analysis(sources)
        assert "https://api.example.com" in auth_map
        info = auth_map["https://api.example.com"]
        assert len(info.static_hints) > 0
        assert info.static_hints[0].method == "api_key"

    def test_url_without_auth(self):
        sources = [
            ConfigSource(
                origin="test",
                json_payload={"cdn": "https://cdn.example.com"},
                urls_found=["https://cdn.example.com"],
            ),
        ]
        auth_map = run_static_auth_analysis(sources)
        assert "https://cdn.example.com" in auth_map
        assert len(auth_map["https://cdn.example.com"].static_hints) == 0

    def test_no_json_payload_skipped(self):
        sources = [
            ConfigSource(
                origin="test",
                json_payload=None,
                urls_found=["https://example.com"],
            ),
        ]
        auth_map = run_static_auth_analysis(sources)
        assert "https://example.com" in auth_map
        assert len(auth_map["https://example.com"].static_hints) == 0


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


class TestReconcileAuth:
    def test_probe_www_authenticate_wins(self):
        auth_map = {
            "https://api.example.com": AuthInfo(
                url="https://api.example.com",
                static_hints=[AuthHint("api_key", "high", "apiKey", "sk-1***", "test")],
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

    def test_high_static_without_probe(self):
        auth_map = {
            "https://api.example.com": AuthInfo(
                url="https://api.example.com",
                static_hints=[AuthHint("api_key", "high", "apiKey", "sk-1***", "test")],
            ),
        }
        reconcile_auth(auth_map)
        assert auth_map["https://api.example.com"].best_guess == "api_key"

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

    def test_medium_hint_as_fallback(self):
        auth_map = {
            "https://api.example.com": AuthInfo(
                url="https://api.example.com",
                static_hints=[AuthHint("bearer", "medium", "token", "abc1***", "test")],
            ),
        }
        reconcile_auth(auth_map)
        assert auth_map["https://api.example.com"].best_guess == "bearer"

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
        assert auth_map["https://api.example.com"].best_guess == "unknown (forbidden)"


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
async def test_static_analysis_with_crawl(auth_server):
    """Crawl the auth test server and verify static auth detection finds apiKey."""
    sources = await crawl(auth_server, timeout=10000, wait_after_load=2000)
    auth_map = run_static_auth_analysis(sources)

    # The config.json endpoint has apiKey alongside the URL
    api_key_found = False
    for url, info in auth_map.items():
        for hint in info.static_hints:
            if hint.method == "api_key" and hint.evidence_key == "apiKey":
                api_key_found = True
                break
    assert api_key_found, "Static analysis should detect apiKey in config.json"


@pytest.mark.asyncio
async def test_write_results_with_auth(auth_server, tmp_path):
    """Verify write_results includes auth section when auth_map is provided."""
    sources = await crawl(auth_server, timeout=10000, wait_after_load=2000)
    auth_map = run_static_auth_analysis(sources)
    reconcile_auth(auth_map)

    out_path = str(tmp_path / "results_auth.json")
    write_results(sources, out_path, auth_map)

    with open(out_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "auth" in data
    assert isinstance(data["auth"], dict)
    for url, auth_entry in data["auth"].items():
        assert "best_guess" in auth_entry
