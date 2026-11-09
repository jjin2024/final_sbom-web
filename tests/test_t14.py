"""T14: Gemini 호출 효율화.
1) 요약 재사용: "요약됨"이 된 항목을 /data/_cache/summaries.json에 저장해 다음 요청에서 다시 쓴다 (R4-3, 후보 C5)
2) 치명적 오류(HTTP 429, 401, 403)가 나면 남은 묶음을 요청하지 않는다 (R4-2)"""
import io
import json
import logging
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import DEFAULT_SUMMARY_CACHE_TTL_DAYS, Settings
from app.main import create_app
from app.osv import Finding
from app.summary import GeminiSource
from app.summary_cache import PROMPT_VERSION, SummaryCache

from .conftest import upload
from .fakes import FakeSource, FakeSummary, many

KST = timezone(timedelta(hours=9))


def at(day, h=10, m=0, s=0):
    return lambda: datetime(2026, 11, day, h, m, s, tzinfo=KST)


def client(data_dir, source, gem, when=None, **settings):
    return TestClient(create_app(Settings(data_dir=data_dir, **settings), vuln_source=source,
                                 summary_source=gem, clock=when or at(9)))


def cache_file(data_dir):
    return data_dir / "_cache" / "summaries.json"


def entries(data_dir):
    return json.loads(cache_file(data_dir).read_text(encoding="utf-8"))["entries"]


def statuses(body):
    return [r["summary_status"] for r in body["table"]]


def report(data_dir, body, project="demo"):
    return (data_dir / project / f"vuln-report-{body['scan_id']}.txt").read_text(encoding="utf-8")


ONE = b"flask==3.0.0\n"


# ---- 사례 74: 같은 파일을 두 번 올리면 두 번째는 호출 0회 ----

def test_case74_second_upload_of_the_same_file_makes_no_gemini_call(data_dir):
    src, gem = FakeSource(many(7)), FakeSummary()
    first = upload(client(data_dir, src, gem, at(9, 10)), content=ONE).json()
    assert statuses(first) == ["요약됨"] * 7 and len(gem.calls) == 2  # 5건 + 2건
    assert first["summary"]["calls"] == 2 and first["summary"]["reused"] == 0
    second = upload(client(data_dir, src, gem, at(9, 11)), content=ONE).json()
    assert len(gem.calls) == 2  # 호출이 늘지 않음
    assert statuses(second) == ["요약됨(재사용)"] * 7
    assert [r["summary"] for r in second["table"]] == [r["summary"] for r in first["table"]]  # 같은 요약문
    assert second["summary"]["text"] == "요약 7건 성공, 0건 실패, 0건 제외"
    assert second["summary"]["calls"] == 0 and second["summary"]["reused"] == 7
    text = report(data_dir, second)
    assert "요약 7건 성공, 0건 실패, 0건 제외\n요약 호출 0회, 재사용 7건\n" in text
    assert text.count("[요약됨(재사용)]") == 7


# ---- 사례 75: 일부만 겹치면 새 항목만 5건 묶음으로 ----

def test_case75_only_new_items_are_requested_in_batches_of_five(data_dir):
    first_src = FakeSource(many(4))
    second_src = FakeSource({("flask", "3.0.0"): many(4)[("flask", "3.0.0")],
                             ("requests", "2.31.0"): [Finding(f"NEW-{i:04d}", "심각") for i in range(1, 8)]})
    gem = FakeSummary()
    upload(client(data_dir, first_src, gem, at(9, 10)), content=ONE)  # flask 4건 저장
    assert [len(c) for c in gem.calls] == [4]
    gem.calls.clear()
    body = upload(client(data_dir, second_src, gem, at(9, 11)), content=b"flask==3.0.0\nrequests==2.31.0\n").json()
    assert [len(c) for c in gem.calls] == [5, 2]  # 새 7건만 5건 + 2건
    sent = {(i.package, i.vuln_id) for call in gem.calls for i in call}
    assert sent == {("requests", f"NEW-{i:04d}") for i in range(1, 8)}  # 요청 본문에 겹친 flask 항목이 없다
    st = [r["summary_status"] for r in body["table"]]
    assert st.count("요약됨(재사용)") == 4 and st.count("요약됨") == 7
    assert body["summary"] == {"succeeded": 11, "failed": 0, "excluded": 0,
                               "text": "요약 11건 성공, 0건 실패, 0건 제외", "calls": 2, "reused": 4}


# ---- 사례 76: 실패한 요약은 저장되지 않아 다시 시도된다 ----

def test_case76_failed_summaries_are_not_cached_and_are_retried(data_dir):
    src = FakeSource(many(12))
    gem = FakeSummary(fail_calls={2})  # 둘째 묶음(5건)만 HTTP 500
    first = upload(client(data_dir, src, gem, at(9, 10)), content=ONE).json()
    assert statuses(first).count("요약 실패") == 5
    assert len(entries(data_dir)) == 7  # 성공한 7건만 저장
    gem2 = FakeSummary()
    second = upload(client(data_dir, src, gem2, at(9, 11)), content=ONE).json()
    assert [len(c) for c in gem2.calls] == [5]  # 실패했던 5건만 다시 시도
    st = statuses(second)
    assert st.count("요약됨(재사용)") == 7 and st.count("요약됨") == 5 and "요약 실패" not in st
    assert len(entries(data_dir)) == 12


def test_excluded_and_no_key_statuses_are_not_cached(data_dir):
    upload(client(data_dir, FakeSource(many(6)), FakeSummary(), at(9, 10), summary_max_items=2), content=ONE)
    assert len(entries(data_dir)) == 2  # 요약 제외 4건은 저장하지 않음
    other = data_dir / "k"
    upload(TestClient(create_app(Settings(data_dir=other), vuln_source=FakeSource(many(3)), clock=at(9, 11))),
           content=ONE)  # 키 없음
    assert not (other / "_cache").exists()


# ---- 사례 77: 캐시 파일이 깨져도 201, 쓰기가 실패하면 경고 ----

@pytest.mark.parametrize("content", [b"{not json", b"", b'["list"]', b'{"entries": 5}',
                                     b'{"entries": {"x": 3}}', b"\xff\xfe\x00bad"])
def test_case77_broken_cache_file_is_ignored(data_dir, content):
    cache_file(data_dir).parent.mkdir(parents=True)
    cache_file(data_dir).write_bytes(content)
    gem = FakeSummary()
    r = upload(client(data_dir, FakeSource(many(3)), gem), content=ONE)
    body = r.json()
    assert r.status_code == 201 and statuses(body) == ["요약됨"] * 3 and len(gem.calls) == 1
    assert body["warnings"] == [] and len(entries(data_dir)) == 3  # 새로 만든 캐시가 저장됨


def test_case77_cache_write_failure_adds_a_warning_but_not_an_error(data_dir):
    (data_dir / "_cache").parent.mkdir(parents=True, exist_ok=True)
    (data_dir / "_cache").write_text("a file where the folder should be")  # 폴더를 만들 수 없다
    gem = FakeSummary()
    r = upload(client(data_dir, FakeSource(many(3)), gem), content=ONE)
    body = r.json()
    assert r.status_code == 201 and statuses(body) == ["요약됨"] * 3
    assert body["warnings"] == ["요약 캐시 저장 실패"]
    report(data_dir, body)  # 보고서는 정상 저장됨


def test_cache_is_written_atomically_without_leftovers(data_dir):
    upload(client(data_dir, FakeSource(many(3)), FakeSummary()), content=ONE)
    assert sorted(p.name for p in (data_dir / "_cache").iterdir()) == ["summaries.json"]


# ---- 사례 78: TTL ----

def test_case78_ttl_zero_never_reuses_and_never_writes(data_dir):
    src, gem = FakeSource(many(3)), FakeSummary()
    upload(client(data_dir, src, gem, at(9, 10), summary_cache_ttl_days=0), content=ONE)
    body = upload(client(data_dir, src, gem, at(9, 11), summary_cache_ttl_days=0), content=ONE).json()
    assert len(gem.calls) == 2 and statuses(body) == ["요약됨"] * 3
    assert body["summary"]["calls"] == 1 and body["summary"]["reused"] == 0
    assert not (data_dir / "_cache").exists()


def test_case78_entries_older_than_the_ttl_are_not_reused(data_dir):
    src, gem = FakeSource(many(3)), FakeSummary()
    upload(client(data_dir, src, gem, at(9, 10), summary_cache_ttl_days=3), content=ONE)
    inside = upload(client(data_dir, src, gem, at(12, 10), summary_cache_ttl_days=3), content=ONE).json()  # 정확히 3일
    assert statuses(inside) == ["요약됨(재사용)"] * 3 and len(gem.calls) == 1
    outside = upload(client(data_dir, src, gem, at(12, 10, 0, 1), summary_cache_ttl_days=3), content=ONE).json()
    assert statuses(outside) == ["요약됨"] * 3 and len(gem.calls) == 2  # 3일을 넘기면 새로 요약
    assert all(e["saved_at"].startswith("2026-11-12T10:00:01") for e in entries(data_dir).values())  # 갱신됨


def test_default_ttl_is_30_days(monkeypatch, tmp_path):
    assert DEFAULT_SUMMARY_CACHE_TTL_DAYS == 30
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SUMMARY_CACHE_TTL_DAYS", raising=False)
    assert Settings.from_env().summary_cache_ttl_days == 30
    monkeypatch.setenv("SUMMARY_CACHE_TTL_DAYS", "7")
    assert Settings.from_env().summary_cache_ttl_days == 7


def test_entries_with_another_prompt_version_are_not_reused(data_dir):
    src, gem = FakeSource(many(3)), FakeSummary()
    upload(client(data_dir, src, gem, at(9, 10)), content=ONE)
    data = json.loads(cache_file(data_dir).read_text(encoding="utf-8"))
    assert all(e["prompt_version"] == PROMPT_VERSION == "v1" for e in data["entries"].values())
    for e in data["entries"].values():
        e["prompt_version"] = "v0"
    cache_file(data_dir).write_text(json.dumps(data), encoding="utf-8")
    body = upload(client(data_dir, src, gem, at(9, 11)), content=ONE).json()
    assert statuses(body) == ["요약됨"] * 3 and len(gem.calls) == 2


def test_cache_entry_shape(data_dir):
    upload(client(data_dir, FakeSource(many(1)), FakeSummary(), at(9, 10, 0, 5)), content=ONE)
    (key, value), = entries(data_dir).items()
    assert json.loads(key) == ["flask", "3.0.0", "TEST-0001"]
    assert value == {"summary": "요약:TEST-0001", "saved_at": "2026-11-09T10:00:05+09:00", "prompt_version": "v1"}


# ---- 사례 79: 429, 401, 403이면 중단, 500이면 계속 ----

@pytest.mark.parametrize("code", [429, 401, 403])
def test_case79_fatal_http_codes_stop_the_remaining_batches(data_dir, code, caplog):
    def opener(req, timeout):
        raise urllib.error.HTTPError(req.full_url, code, "err", {}, io.BytesIO(b'{"error":"secret-body"}'))
    calls = []

    def counting(req, timeout):
        calls.append(1)
        return opener(req, timeout)

    gem = GeminiSource("key-xyz-123", "https://gemini.example", "m", 5, 100, opener=counting)
    with caplog.at_level(logging.WARNING, logger="sbom.summary"):
        r = upload(client(data_dir, FakeSource(many(12)), gem), content=ONE)
    body = r.json()
    assert r.status_code == 201 and len(calls) == 1  # 첫 묶음만 요청
    assert set(statuses(body)) == {"요약 실패"} and len(body["table"]) == 12  # 남은 항목도 요약 실패
    assert body["summary"]["text"] == "요약 0건 성공, 12건 실패, 0건 제외" and body["summary"]["calls"] == 1
    logs = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "요약 중단" in logs and f"HTTP {code}" in logs
    assert "key-xyz-123" not in logs + r.text and "secret-body" not in logs + r.text and "gemini.example" not in logs
    assert "HTTP" not in r.text  # 응답에는 원인을 넣지 않는다
    assert not cache_file(data_dir).exists()  # 실패는 저장하지 않음


def test_case79_fatal_failure_in_the_middle_keeps_earlier_successes(data_dir):
    gem = FakeSummary(fatal_calls={2})
    body = upload(client(data_dir, FakeSource(many(17)), gem), content=ONE).json()
    assert len(gem.calls) == 2  # 셋째, 넷째 묶음은 요청하지 않음
    st = statuses(body)
    assert st.count("요약됨") == 5 and st.count("요약 실패") == 10  # 표는 15행까지, 집계는 17건 전체
    assert body["summary"]["text"] == "요약 5건 성공, 12건 실패, 0건 제외"
    assert len(entries(data_dir)) == 5


@pytest.mark.parametrize("code", [500, 503])
def test_case79_other_failures_keep_trying_the_next_batches(data_dir, code):
    def opener(req, timeout):
        raise urllib.error.HTTPError(req.full_url, code, "err", {}, io.BytesIO(b"{}"))
    calls = []
    gem = GeminiSource("k", "https://gemini.example", "m", 5, 100,
                       opener=lambda req, timeout: (calls.append(1), opener(req, timeout))[1])
    body = upload(client(data_dir, FakeSource(many(12)), gem), content=ONE).json()
    assert len(calls) == 3  # 모든 묶음을 시도
    assert set(statuses(body)) == {"요약 실패"}


def test_case79_timeout_and_truncation_are_not_fatal(data_dir):
    gem = FakeSummary(fail_calls={1})
    body = upload(client(data_dir, FakeSource(many(10)), gem), content=ONE).json()
    assert len(gem.calls) == 2 and statuses(body) == ["요약 실패"] * 5 + ["요약됨"] * 5


# ---- 사례 80: 키가 없으면 캐시가 있어도 요약 안 함 ----

def test_case80_without_a_key_the_cache_is_not_used(data_dir):
    src = FakeSource(many(3))
    upload(client(data_dir, src, FakeSummary(), at(9, 10)), content=ONE)  # 캐시를 만든다
    assert len(entries(data_dir)) == 3
    r = upload(TestClient(create_app(Settings(data_dir=data_dir), vuln_source=src, clock=at(9, 11))), content=ONE)
    body = r.json()
    assert set(statuses(body)) == {"요약 안 함(API 키 없음)"}
    assert body["summary"] == {"skipped_reason": "API 키 없음", "message": "요약 건너뜀(API 키 없음)"}
    assert "calls" not in body["summary"]
    assert "요약 호출" not in report(data_dir, body)  # 건너뛴 경우에는 줄이 없다


def test_no_usage_line_when_there_is_nothing_to_summarize(data_dir):
    body = upload(client(data_dir, FakeSource({}), FakeSummary()), content=ONE).json()
    assert body["summary"]["skipped_reason"] == "요약할 취약점 없음" and "calls" not in body["summary"]
    assert "요약 호출" not in report(data_dir, body)


# ---- 사례 81: 다른 프로젝트에서도 재사용 ----

def test_case81_other_projects_reuse_the_same_items(data_dir):
    src, gem = FakeSource(many(4)), FakeSummary()
    upload(client(data_dir, src, gem, at(9, 10)), project="alpha", content=ONE)
    body = upload(client(data_dir, src, gem, at(9, 10)), project="beta", content=ONE).json()
    assert len(gem.calls) == 1 and statuses(body) == ["요약됨(재사용)"] * 4
    # 캐시 폴더는 프로젝트가 아니다
    c = client(data_dir, src, gem)
    assert c.get("/api/projects/_cache/scans").status_code == 400
    assert upload(c, project="_cache", content=ONE).status_code == 400


# ---- 사례 82: 응답, 보고서, 화면 ----

def test_case82_response_report_and_screen_show_calls_and_reuse(data_dir):
    src, gem = FakeSource(many(6)), FakeSummary()
    body = upload(client(data_dir, src, gem, at(9, 10)), content=ONE).json()
    assert body["summary"] == {"succeeded": 6, "failed": 0, "excluded": 0,
                               "text": "요약 6건 성공, 0건 실패, 0건 제외", "calls": 2, "reused": 0}
    text = report(data_dir, body)
    assert text.endswith("## 요약 집계\n요약 6건 성공, 0건 실패, 0건 제외\n요약 호출 2회, 재사용 0건\n")
    html = (Path(__file__).resolve().parent.parent / "app" / "static" / "index.html").read_text(encoding="utf-8")
    assert "요약 호출 '+s.calls+'회, 재사용 '+s.reused+'건" in html  # 집계 줄 옆에 표시(esc 경유)
    assert "esc('요약 호출" in html


def test_cache_unit_semantics(tmp_path):
    now = datetime(2026, 11, 9, 10, tzinfo=KST)
    c = SummaryCache(tmp_path, 30, now)
    assert c.get("a", "1", "X") is None
    c.put("a", "1", "X", "text")
    assert c.get("a", "1", "X") == "text" and c.get("a", "1", "Y") is None and c.get("b", "1", "X") is None
    c.save()
    assert SummaryCache(tmp_path, 30, now + timedelta(days=30)).get("a", "1", "X") == "text"
    assert SummaryCache(tmp_path, 30, now + timedelta(days=30, seconds=1)).get("a", "1", "X") is None
    assert SummaryCache(tmp_path, 0, now).get("a", "1", "X") is None
