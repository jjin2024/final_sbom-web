"""T9 확인 사례 37~39 (3.2): AI 요약 실패 처리 (R4-2)."""
import http.client
import io
import logging
import os
import urllib.error

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.summary import GeminiSource, SummaryFailed, SummaryItem

from .conftest import FILE_D, FILE_F, upload
from .fakes import SET_D, SET_F, FakeSource, FakeSummary, many
from .test_t8 import FakeHttp, gemini_reply, make_gemini, report, statuses


def by_status(body):
    out = {}
    for r in body["table"]:
        out.setdefault(r["summary_status"], []).append(r["vuln_id"])
    return out


# ---- 사례 37 ----

def test_case37_middle_batch_fails_others_kept(make_client, data_dir):
    gem = FakeSummary(fail_calls={2})  # 두 번째 요청만 오류
    r = upload(make_client(FakeSource(many(12)), summary_source=gem), content=b"flask==3.0.0\n")
    body = r.json()
    assert r.status_code == 201
    assert [len(c) for c in gem.calls] == [5, 5, 2]  # 오류 뒤에도 셋째 요청이 감
    table = body["table"]
    assert [x["summary_status"] for x in table] == ["요약됨"] * 5 + ["요약 실패"] * 5 + ["요약됨"] * 2
    assert all(x["summary"].startswith("요약:") for x in table if x["summary_status"] == "요약됨")
    assert all(x["summary"] == "" for x in table if x["summary_status"] == "요약 실패")
    assert body["summary"] == {"succeeded": 7, "failed": 5, "excluded": 0,
                               "text": "요약 7건 성공, 5건 실패, 0건 제외", "calls": 3, "reused": 0}
    assert len(table) == 12 and body["vulnerabilities_total"] == 12  # 표에 12건 모두
    text = report(data_dir, body)
    assert all(f"TEST-{i:04d}" in text for i in range(1, 13))  # 보고서에도 12건 모두
    assert text.count("[요약됨]") == 7 and text.count("[요약 실패]") == 5
    assert "요약 7건 성공, 5건 실패, 0건 제외" in text
    assert text.count(": 요약:") == 7  # 요약문은 성공한 7건만


# ---- 사례 38 ----

@pytest.mark.parametrize("code", [400, 401, 403, 429, 500, 503])
def test_case38_every_error_status_marks_all_failed(data_dir, code):
    def opener(req, timeout):
        raise urllib.error.HTTPError(req.full_url, code, "err", {}, io.BytesIO(b'{"error":{"message":"API key not valid"}}'))

    src = GeminiSource("bad-key-123", "https://gemini.example", "m", 5, 100, opener=opener)
    c = TestClient(create_app(Settings(data_dir=data_dir), vuln_source=FakeSource(SET_D), summary_source=src))
    r = upload(c, content=FILE_D)
    body = r.json()
    assert r.status_code == 201  # 점검은 성공
    assert set(statuses(body).values()) == {"요약 실패"}
    assert body["summary"]["text"] == "요약 0건 성공, 3건 실패, 0건 제외"
    assert len(body["table"]) == 3  # 취약점 표는 정상
    text = report(data_dir, body)
    assert "TEST-0001 flask 3.0.0 높음 [요약 실패]" in text and "요약 0건 성공, 3건 실패, 0건 제외" in text
    assert "bad-key-123" not in r.text + text  # 키는 어디에도 없다


# ---- 사례 39 (가짜 HTTP로 먼저. 실제 호출은 아래 별도 시험) ----

def test_case39_incomplete_response_marks_the_batch_failed(data_dir):
    http_fake = FakeHttp(lambda n: gemini_reply(n, finish="MAX_TOKENS"))  # 토큰 부족으로 잘림
    src = GeminiSource("k", "https://gemini.example", "m", 5, 1, opener=http_fake)
    c = TestClient(create_app(Settings(data_dir=data_dir), vuln_source=FakeSource(SET_D), summary_source=src))
    body = upload(c, content=FILE_D).json()
    assert set(statuses(body).values()) == {"요약 실패"}
    assert body["summary"]["failed"] == 3 and len(body["table"]) == 3
    assert http_fake.requests[0]["body"]["generationConfig"]["maxOutputTokens"] == 1


@pytest.mark.skipif(
    os.environ.get("GEMINI_LIVE_TEST") != "1" or not os.environ.get("GEMINI_API_KEY"),
    reason="GEMINI_LIVE_TEST=1이고 GEMINI_API_KEY가 설정된 터미널에서만 실제 Gemini 호출",
)
def test_case39_real_gemini_with_one_output_token(data_dir, caplog):
    caplog.set_level(logging.WARNING, logger="sbom.summary")
    s = Settings(data_dir=data_dir, gemini_api_key=os.environ["GEMINI_API_KEY"], gemini_max_output_tokens=1,
                 gemini_timeout=60)
    c = TestClient(create_app(s, vuln_source=FakeSource(SET_D)))  # 실제 Gemini, 가짜 OSV
    body = upload(c, content=FILE_D).json()
    assert set(statuses(body).values()) == {"요약 실패"}
    assert body["summary"]["failed"] == 3 and len(body["table"]) == 3
    # 문서의 의도는 "정상 완료되지 않은 응답"(토큰 부족으로 잘림). 429나 400 같은 다른 사유로 실패한 것이면
    # 통과하지 않고 사유를 보여 준다.
    reasons = [m for m in caplog.messages if "요약 묶음 실패" in m]
    assert reasons, "요약 실패 로그가 없음"
    assert any("not completed" in m for m in reasons), f"실패 사유가 응답 미완료(토큰 부족)가 아님: {reasons}"


# ---- 그 밖의 경계 ----

def test_all_batches_fail_but_every_batch_is_still_tried(make_client):
    gem = FakeSummary(fail_calls={1, 2, 3})
    body = upload(make_client(FakeSource(many(12)), summary_source=gem), content=b"flask==3.0.0\n").json()
    assert len(gem.calls) == 3  # 실패해도 멈추지 않고 문서대로 이후 묶음을 계속 시도
    assert body["summary"]["text"] == "요약 0건 성공, 12건 실패, 0건 제외"


def test_first_batch_fails_later_ones_succeed(make_client):
    body = upload(make_client(FakeSource(many(12)), summary_source=FakeSummary(fail_calls={1})),
                  content=b"flask==3.0.0\n").json()
    assert body["summary"]["text"] == "요약 7건 성공, 5건 실패, 0건 제외"
    assert [x["summary_status"] for x in body["table"][:5]] == ["요약 실패"] * 5


def test_failures_and_exclusions_are_counted_separately(make_client):
    body = upload(make_client(FakeSource(SET_F), summary_source=FakeSummary(fail_calls={1}), summary_max_items=2),
                  content=FILE_F).json()
    assert body["summary"]["text"] == "요약 0건 성공, 2건 실패, 3건 제외"
    assert by_status(body) == {"요약 실패": ["TEST-0001", "TEST-0002"],
                               "요약 제외(한도 초과)": ["TEST-0003", "TEST-0004", "TEST-0005"]}


def test_a_source_returning_the_wrong_number_of_summaries_counts_as_failed(make_client):
    class Short(FakeSummary):
        def summarize(self, items):
            super().summarize(items)
            return ["only one"]

    body = upload(make_client(FakeSource(SET_D), summary_source=Short()), content=FILE_D).json()
    assert body["summary"]["text"] == "요약 0건 성공, 3건 실패, 0건 제외"


def test_failure_reason_goes_to_the_server_log_only(make_client, caplog):
    caplog.set_level(logging.WARNING, logger="sbom.summary")
    r = upload(make_client(FakeSource(many(5)), summary_source=FakeSummary(fail_calls={1})), content=b"flask==3.0.0\n")
    assert any("요약 묶음 실패" in m and "HTTP 500" in m for m in caplog.messages)
    assert "HTTP 500" not in r.text  # 응답에는 원인을 넣지 않는다


@pytest.mark.parametrize("exc", [
    http.client.IncompleteRead(b"partial"),  # 응답이 중간에 잘림
    http.client.RemoteDisconnected("closed"),
    ConnectionResetError(),
    TimeoutError(),
])
def test_truncated_or_dropped_responses_are_summary_failures_not_server_errors(exc):
    def opener(req, timeout):
        raise exc

    with pytest.raises(SummaryFailed):
        make_gemini(opener).summarize([SummaryItem("a", "1", "X-1")])


def test_incomplete_read_while_reading_the_body_is_handled():
    class Broken(io.BytesIO):
        def read(self, *a):
            raise http.client.IncompleteRead(b"par")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with pytest.raises(SummaryFailed):
        make_gemini(lambda req, timeout: Broken()).summarize([SummaryItem("a", "1", "X-1")])


def test_summary_failure_never_loses_the_scan_files(make_client, data_dir):
    body = upload(make_client(FakeSource(SET_D), summary_source=FakeSummary(fail_calls={1})), content=FILE_D).json()
    folder = data_dir / "demo"
    assert (folder / f"sbom-{body['scan_id']}.txt").exists()
    assert (folder / f"vuln-report-{body['scan_id']}.txt").exists()
    assert body["links"]["report"]
