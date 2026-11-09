"""T8 확인 사례 31~36 (3.2): AI 요약 (R4). 27, 30의 "Gemini 호출 0회"도 여기서 판정한다.
요약 실패 처리(R4-2, 사례 37~39)는 T9."""
import io
import json

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.osv import Finding
from app.summary import GeminiSource, SummaryFailed, SummaryItem

from .conftest import FILE_A, FILE_D, FILE_F, upload
from .fakes import SET_D, SET_F, FakeSource, FakeSummary, many


def statuses(body):
    return {r["vuln_id"]: r["summary_status"] for r in body["table"]}


def report(data_dir, body, project="demo"):
    return (data_dir / project / f"vuln-report-{body['scan_id']}.txt").read_text(encoding="utf-8")


# ---- 사례 31 ----

def test_case31_all_summarized_and_only_allowed_fields_are_sent(make_client, data_dir):
    gem = FakeSummary()
    r = upload(make_client(FakeSource(SET_D), summary_source=gem), project="secretproj",
               content=FILE_D, filename="my-private-deps.txt")
    body = r.json()
    assert r.status_code == 201
    assert statuses(body) == {"TEST-0001": "요약됨", "TEST-0002": "요약됨", "TEST-0003": "요약됨"}
    assert body["table"][0]["summary"] == "요약:TEST-0001"
    assert body["summary"] == {"succeeded": 3, "failed": 0, "excluded": 0,
                               "text": "요약 3건 성공, 0건 실패, 0건 제외", "calls": 1, "reused": 0}
    # 요약기가 받는 것은 패키지명, 버전, 취약점 ID뿐이다 (프로젝트 이름, 파일 이름·내용은 전달 경로가 없음)
    assert [(i.package, i.version, i.vuln_id) for i in gem.calls[0]] == [
        ("flask", "3.0.0", "TEST-0001"), ("requests", "2.31.0", "TEST-0002"),
        ("django", "4.2.0", "TEST-0003")]
    assert all(set(vars(i)) == {"package", "version", "vuln_id"} for c in gem.calls for i in c)
    # 보고서에도 상태, 요약, 집계가 들어간다
    text = report(data_dir, body, "secretproj")
    assert "TEST-0001 flask 3.0.0 높음 [요약됨]" in text
    assert "TEST-0001 flask 3.0.0: 요약:TEST-0001" in text
    assert "## 요약 집계\n요약 3건 성공, 0건 실패, 0건 제외" in text


# ---- 사례 32 ----

def test_case32_limit_excludes_the_rest(make_client, data_dir):
    gem = FakeSummary()
    r = upload(make_client(FakeSource(SET_F), summary_source=gem, summary_max_items=2), content=FILE_F)
    body = r.json()
    assert statuses(body) == {
        "TEST-0001": "요약됨", "TEST-0002": "요약됨",
        "TEST-0003": "요약 제외(한도 초과)", "TEST-0004": "요약 제외(한도 초과)",
        "TEST-0005": "요약 제외(한도 초과)",
    }
    assert body["summary"]["text"] == "요약 2건 성공, 0건 실패, 3건 제외"
    assert len(body["table"]) == 5  # 표(15행 이내)에는 5건 모두
    assert len(gem.calls) == 1 and len(gem.calls[0]) == 2  # Gemini 요청 1회(2건)
    assert [t["summary"] for t in body["table"][2:]] == ["", "", ""]
    assert "요약 2건 성공, 0건 실패, 3건 제외" in report(data_dir, body)


# ---- 사례 33 ----

@pytest.mark.parametrize("n,excluded", [(50, 0), (51, 1)])
def test_case33_default_limit_50_in_batches_of_5(make_client, n, excluded):
    gem = FakeSummary()
    r = upload(make_client(FakeSource(many(n)), summary_source=gem), content=b"flask==3.0.0\n")
    body = r.json()
    assert body["vulnerabilities_total"] == n
    assert body["summary"]["excluded"] == excluded and body["summary"]["succeeded"] == 50
    assert len(gem.calls) == 10 and all(len(c) == 5 for c in gem.calls)
    # 심각도 높은 순으로 선정: 첫 묶음은 표의 맨 앞 5건
    assert [i.vuln_id for i in gem.calls[0]] == [t["vuln_id"] for t in body["table"][:5]]


# ---- 사례 34 ----

def test_case34_no_api_key_skips_summary(client, data_dir, source, monkeypatch):
    import app.main as main
    source.responses = SET_D
    monkeypatch.setattr(main, "GeminiSource", lambda *a, **k: pytest.fail("키가 없으면 Gemini를 만들지 않는다"))
    r = upload(client, content=FILE_D)
    body = r.json()
    assert r.status_code == 201
    assert body["summary"] == {"skipped_reason": "API 키 없음", "message": "요약 건너뜀(API 키 없음)"}
    assert set(statuses(body).values()) == {"요약 안 함(API 키 없음)"}
    assert len(body["table"]) == 3  # 취약점 표는 정상
    text = report(data_dir, body)
    assert "TEST-0001 flask 3.0.0 높음 [요약 안 함(API 키 없음)]" in text
    assert "요약 건너뜀(API 키 없음)" in text


def test_blank_api_key_counts_as_no_key(data_dir, monkeypatch):
    import app.main as main
    monkeypatch.setattr(main, "GeminiSource", lambda *a, **k: pytest.fail("빈 키로 만들면 안 됨"))
    c = TestClient(create_app(Settings(data_dir=data_dir, gemini_api_key=""), vuln_source=FakeSource(SET_D)))
    assert upload(c, content=FILE_D).json()["summary"]["skipped_reason"] == "API 키 없음"


def test_api_key_in_settings_creates_gemini_source(data_dir, monkeypatch):
    import app.main as main
    made = []

    def fake_source(*args):
        made.append(args)
        return FakeSummary()

    monkeypatch.setattr(main, "GeminiSource", fake_source)
    c = TestClient(create_app(Settings(data_dir=data_dir, gemini_api_key="k-1", gemini_model="m-x"),
                              vuln_source=FakeSource(SET_D)))
    body = upload(c, content=FILE_D).json()
    assert len(made) == 1 and made[0][0] == "k-1" and made[0][2] == "m-x"
    assert body["summary"]["succeeded"] == 3


# ---- 사례 35 ----

def test_case35_unknown_severity_order_and_limit(make_client):
    responses = {("flask", "3.0.0"): [Finding("TEST-0012", None), Finding("TEST-0011", None),
                                      Finding("TEST-0010", "높음")]}
    results = []
    for _ in range(2):  # 같은 입력으로 다시 요청해도 같은 결과
        gem = FakeSummary()
        body = upload(make_client(FakeSource(responses), summary_source=gem, summary_max_items=2,
                                       summary_cache_ttl_days=0),  # 캐시를 쓰면 두 번째는 재사용되므로 끔
                      content=b"flask==3.0.0\n").json()
        results.append([(t["vuln_id"], t["severity"], t["summary_status"]) for t in body["table"]])
        import time
        time.sleep(1.1)  # 같은 시각(초) 충돌 방지
    assert results[0] == [
        ("TEST-0010", "높음", "요약됨"),
        ("TEST-0011", "알 수 없음", "요약됨"),
        ("TEST-0012", "알 수 없음", "요약 제외(한도 초과)"),
    ]
    assert results[0] == results[1]


# ---- 사례 36 ----

def test_case36_twelve_items_make_three_requests(make_client):
    gem = FakeSummary()
    body = upload(make_client(FakeSource(many(12)), summary_source=gem), content=b"flask==3.0.0\n").json()
    assert [len(c) for c in gem.calls] == [5, 5, 2]
    assert set(statuses(body).values()) == {"요약됨"}
    assert body["summary"]["text"] == "요약 12건 성공, 0건 실패, 0건 제외"


def test_batch_size_is_configurable(make_client):
    gem = FakeSummary()
    upload(make_client(FakeSource(many(7)), summary_source=gem, summary_batch_size=3),
           content=b"flask==3.0.0\n")
    assert [len(c) for c in gem.calls] == [3, 3, 1]


# ---- 사례 27, 30: Gemini 호출 0회 ----

def test_case27_no_vulnerabilities_makes_no_gemini_call(make_client, data_dir):
    gem = FakeSummary()
    body = upload(make_client(summary_source=gem), content=FILE_A).json()  # 응답 세트 E
    assert gem.calls == []
    assert body["summary"] == {"skipped_reason": "요약할 취약점 없음", "message": "요약 단계 생략(요약할 취약점 없음)"}
    text = report(data_dir, body)
    assert "발견된 취약점 없음" in text and "요약 단계 생략(요약할 취약점 없음)" in text


def test_case30_lookup_failure_makes_no_gemini_call(make_client):
    gem = FakeSummary()
    r = upload(make_client(FakeSource(SET_D, fail=True), summary_source=gem), content=FILE_D)
    assert r.status_code == 502 and gem.calls == []


# ---- GeminiSource: 실제 요청 형식 (가짜 HTTP) ----

class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def gemini_reply(n, finish="STOP", texts=None):
    results = [{"id": i, "description": f"설명{i}", "upgrade": f"권장{i}"} for i in range(1, n + 1)]
    return {"candidates": [{"finishReason": finish,
                            "content": {"parts": [{"text": json.dumps(results, ensure_ascii=False)}]}}]}


class FakeHttp:
    """urlopen 대신 쓰는 가짜. 요청(주소, 헤더, 본문)을 기록하고 항목 수에 맞는 정상 응답을 준다."""

    def __init__(self, reply=None):
        self.requests = []
        self.reply = reply

    def __call__(self, req, timeout):
        body = json.loads(req.data)
        self.requests.append({"url": req.full_url, "key": req.get_header("X-goog-api-key"),
                              "body": body, "raw": req.data.decode("utf-8"), "timeout": timeout})
        prompt = body["contents"][0]["parts"][0]["text"]
        n = len(json.loads(prompt.split("입력:\n", 1)[1]))
        reply = self.reply(n) if callable(self.reply) else (self.reply or gemini_reply(n))
        return _Resp(json.dumps(reply).encode("utf-8"))


def make_gemini(http, **kw):
    return GeminiSource("test-key-123456", "https://gemini.example/", "model-x", 7, kw.get("tokens", 321), opener=http)


def test_gemini_request_shape_and_secrecy():
    http = FakeHttp()
    out = make_gemini(http).summarize([SummaryItem("flask", "3.0.0", "TEST-0001"),
                                       SummaryItem("requests", "2.31.0", "TEST-0002")])
    assert out == ["설명1 권장: 권장1", "설명2 권장: 권장2"]
    req = http.requests[0]
    assert req["url"] == "https://gemini.example/v1beta/models/model-x:generateContent"
    assert req["key"] == "test-key-123456"  # 키는 헤더로만
    assert "test-key-123456" not in req["url"] and "test-key-123456" not in req["raw"]
    assert req["body"]["generationConfig"]["maxOutputTokens"] == 321
    assert req["timeout"] == 7
    sent = json.loads(req["body"]["contents"][0]["parts"][0]["text"].split("입력:\n", 1)[1])
    assert sent == [
        {"id": 1, "package": "flask", "version": "3.0.0", "vulnerability": "TEST-0001"},
        {"id": 2, "package": "requests", "version": "2.31.0", "vulnerability": "TEST-0002"},
    ]


def test_case31_end_to_end_with_real_gemini_source_sends_nothing_else(data_dir):
    http = FakeHttp()
    src = GeminiSource("test-key-123456", "https://gemini.example", "m", 5, 100, opener=http)
    c = TestClient(create_app(Settings(data_dir=data_dir), vuln_source=FakeSource(SET_D), summary_source=src))
    secret_file = b"# internal-only-comment\nflask==3.0.0\nrequests==2.31.0\ndjango==4.2.0\n"
    r = upload(c, project="topsecret-proj", content=secret_file, filename="payroll-system-deps.txt")
    assert r.status_code == 201 and r.json()["summary"]["succeeded"] == 3
    sent = " ".join(q["raw"] for q in http.requests)
    for forbidden in ["topsecret-proj", "payroll-system-deps", "internal-only-comment", "demo"]:
        assert forbidden not in sent
    for allowed in ["flask", "3.0.0", "TEST-0001", "django", "4.2.0"]:
        assert allowed in sent
    # 키가 응답, 저장된 파일, 주소 어디에도 없다
    everything = r.text + "".join(p.read_text(encoding="utf-8") for p in data_dir.rglob("*.txt"))
    assert "test-key-123456" not in everything
    assert all("test-key-123456" not in q["url"] for q in http.requests)


@pytest.mark.parametrize("reply", [
    gemini_reply(2, finish="MAX_TOKENS"),                      # 토큰 부족으로 잘림
    gemini_reply(2, finish="SAFETY"),                          # 안전 차단
    {"candidates": []},                                        # 후보 없음
    {"error": {"code": 401}},                                  # 오류 본문
    gemini_reply(1),                                           # 항목 수가 모자람
    {"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": "not json"}]}}]},
    {"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": json.dumps([{"id": 1}])}]}}]},
])
def test_gemini_source_rejects_anything_but_a_complete_response(reply):
    src = make_gemini(FakeHttp(reply))
    with pytest.raises(SummaryFailed):
        src.summarize([SummaryItem("a", "1", "X-1"), SummaryItem("b", "2", "X-2")])


@pytest.mark.parametrize("exc", [OSError("down"), TimeoutError(), ValueError("bad json")])
def test_gemini_source_network_failures_become_summary_failed(exc):
    def opener(req, timeout):
        raise exc

    with pytest.raises(SummaryFailed) as info:
        make_gemini(opener).summarize([SummaryItem("a", "1", "X-1")])
    assert "test-key-123456" not in str(info.value)


# ---- 실제 Gemini 1회 확인 (키와 네트워크 필요, 기본은 건너뜀) ----

@pytest.mark.skipif(
    __import__("os").environ.get("GEMINI_LIVE_TEST") != "1"
    or not __import__("os").environ.get("GEMINI_API_KEY"),
    reason="GEMINI_LIVE_TEST=1이고 GEMINI_API_KEY가 설정된 터미널에서만 실제 Gemini 호출",
)
def test_real_gemini_returns_a_summary_for_each_item():
    s = Settings.from_env()
    src = GeminiSource(s.gemini_api_key, s.gemini_url, s.gemini_model, s.gemini_timeout,
                       s.gemini_max_output_tokens, s.gemini_thinking_level)
    out = src.summarize([SummaryItem("flask", "3.0.0", "CVE-2026-27205"),
                         SummaryItem("requests", "2.31.0", "CVE-2024-35195")])
    assert len(out) == 2 and all(isinstance(t, str) and len(t) > 10 for t in out)


def test_http_error_keeps_only_the_status_code_for_diagnosis():
    import urllib.error

    def opener(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b'{"error":"model x not found"}'))

    with pytest.raises(SummaryFailed) as info:
        make_gemini(opener).summarize([SummaryItem("a", "1", "X-1")])
    assert str(info.value) == "HTTP 404"  # 키, 주소, 응답 본문은 메시지에 없다


def test_thinking_level_is_sent_only_when_set():
    on, off = FakeHttp(), FakeHttp()
    item = [SummaryItem("a", "1", "X-1")]
    GeminiSource("k", "https://g.example", "m", 5, 100, "low", opener=on).summarize(item)
    GeminiSource("k", "https://g.example", "m", 5, 100, "", opener=off).summarize(item)
    assert on.requests[0]["body"]["generationConfig"]["thinkingConfig"] == {"thinkingLevel": "low"}
    assert "thinkingConfig" not in off.requests[0]["body"]["generationConfig"]  # 지원하지 않는 모델용


def test_thinking_level_setting_default_and_env(monkeypatch, data_dir):
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.delenv("GEMINI_THINKING_LEVEL", raising=False)
    assert Settings.from_env().gemini_thinking_level == "low"
    monkeypatch.setenv("GEMINI_THINKING_LEVEL", "")
    assert Settings.from_env().gemini_thinking_level == ""  # 빈 값이면 끔
    monkeypatch.setenv("GEMINI_THINKING_LEVEL", " minimal ")
    assert Settings.from_env().gemini_thinking_level == "minimal"


def test_model_name_from_the_model_list_works_as_is():
    http = FakeHttp()
    GeminiSource("k", "https://g.example", "models/gemini-x", 5, 100, opener=http).summarize(
        [SummaryItem("a", "1", "X-1")])
    assert http.requests[0]["url"] == "https://g.example/v1beta/models/gemini-x:generateContent"


# ---- 키가 새지 않는다 ----

def test_settings_repr_hides_the_api_key(data_dir):
    s = Settings(data_dir=data_dir, gemini_api_key="super-secret-key")
    assert "super-secret-key" not in repr(s) and "super-secret-key" not in str(s)


def test_settings_from_env_reads_the_key_only_from_environment(monkeypatch, data_dir):
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("GEMINI_API_KEY", "  env-key-1  ")
    s = Settings.from_env()
    assert s.gemini_api_key == "env-key-1"
    monkeypatch.delenv("GEMINI_API_KEY")
    assert Settings.from_env().gemini_api_key == ""
    monkeypatch.setenv("SUMMARY_MAX_ITEMS", "7")
    monkeypatch.setenv("SUMMARY_BATCH_SIZE", "3")
    monkeypatch.setenv("GEMINI_MODEL", "m-env")
    monkeypatch.setenv("GEMINI_MAX_OUTPUT_TOKENS", "9")
    monkeypatch.setenv("GEMINI_TIMEOUT_SECONDS", "12.5")
    s = Settings.from_env()
    assert (s.summary_max_items, s.summary_batch_size, s.gemini_model, s.gemini_max_output_tokens) == (7, 3, "m-env", 9)
    assert s.gemini_timeout == 12.5


def test_gemini_gets_its_own_longer_timeout_than_osv(data_dir, monkeypatch):
    import app.main as main
    made = []
    monkeypatch.setattr(main, "GeminiSource", lambda *a: made.append(a) or FakeSummary())
    create_app(Settings(data_dir=data_dir, gemini_api_key="k", external_timeout=10), vuln_source=FakeSource())
    assert made[0][3] == 60.0 and made[0][3] > 10  # 모델 응답은 OSV보다 느려서 따로 둔다
    assert Settings(data_dir=data_dir).gemini_model == "gemini-3.5-flash"


def test_api_key_is_not_written_anywhere_in_the_source_tree():
    from pathlib import Path
    root = Path(__file__).parent.parent
    for p in list((root / "app").rglob("*.py")) + [root / "Dockerfile", root / ".dockerignore"]:
        text = p.read_text(encoding="utf-8")
        assert "AIza" not in text, p  # Google API 키의 접두사
