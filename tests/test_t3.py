"""T3 확인 사례 23~29 (3.2) + 심각도 변환(4.5)과 OSV 응답 해석 단위 시험."""
import io
import json
import os

import pytest

from app.osv import Finding, LookupFailed, OsvSource, parse_record
from app.severity import cvss3_score, from_text, from_vectors

from .conftest import FILE_A, FILE_D, FILE_E, FILE_I, upload
from .fakes import SET_D, FakeSource, many


def files_in(data_dir, prefix, project="demo"):
    return sorted((data_dir / project).glob(f"{prefix}-*.txt"))


def report_text(data_dir, scan_id, project="demo"):
    return (data_dir / project / f"vuln-report-{scan_id}.txt").read_text(encoding="utf-8")


def test_case23_vulnerabilities_found(make_client):
    src = FakeSource(SET_D)
    r = upload(make_client(src), content=FILE_D)
    assert r.status_code == 201
    body = r.json()
    assert body["vulnerabilities_total"] == 3
    got = [(x["package"], x["version"], x["vuln_id"], x["severity"]) for x in body["table"]]
    assert got == [
        ("flask", "3.0.0", "TEST-0001", "높음"),
        ("requests", "2.31.0", "TEST-0002", "보통"),
        ("django", "4.2.0", "TEST-0003", "낮음"),
    ]
    assert all(x["package"] != "click" for x in body["table"])  # 취약점 없는 항목은 표에 없음


def test_case24_duplicates_are_looked_up_once(make_client):
    src = FakeSource(SET_D)
    r = upload(make_client(src), content=FILE_I)
    body = r.json()
    assert body["collected"] == 3
    assert sorted(src.calls) == [("flask", "3.0.0", "PyPI"), ("requests", "2.31.0", "PyPI")]
    assert [x["vuln_id"] for x in body["table"]].count("TEST-0001") == 1


def test_case26_table_order_columns_and_report_name(make_client, data_dir):
    src = FakeSource(SET_D)
    r = upload(make_client(src), content=FILE_D)
    body = r.json()
    assert [x["vuln_id"] for x in body["table"]] == ["TEST-0001", "TEST-0002", "TEST-0003"]
    assert set(body["table"][0]) == {
        "package", "version", "ecosystem", "vuln_id", "severity", "summary_status", "summary"
    }
    sbom = files_in(data_dir, "sbom")
    report = files_in(data_dir, "vuln-report")
    assert len(sbom) == 1 and len(report) == 1
    # 파일명 시각이 같은 요청의 목록 파일과 같음
    assert sbom[0].name.removeprefix("sbom-") == report[0].name.removeprefix("vuln-report-")
    assert body["scan_id"] in report[0].name
    text = report[0].read_text(encoding="utf-8")
    assert "KST" in text
    assert text.index("TEST-0001") < text.index("TEST-0002") < text.index("TEST-0003")


def test_case27_no_vulnerabilities(client, data_dir, source):
    r = upload(client, content=FILE_E)
    body = r.json()
    assert r.status_code == 201
    assert body["vulnerabilities_total"] == 0 and body["table"] == []
    assert body["message"] == "발견된 취약점 없음"
    assert "skipped_reason" in body["summary"]  # 요약 단계 생략 표시
    assert "발견된 취약점 없음" in report_text(data_dir, body["scan_id"])
    # Gemini 호출 0회는 T8에서 요약 호출이 생긴 뒤에 판정한다


def test_case28_table_limited_to_15_rows(make_client, data_dir):
    src = FakeSource(many(20))
    r = upload(make_client(src), content=b"flask==3.0.0\n")
    body = r.json()
    assert body["vulnerabilities_total"] == 20
    assert len(body["table"]) == 15 and body["table_omitted"] == 5
    assert body["message"] == "외 5건은 보고서 참조"
    # 심각도 높은 순: 심각 5건이 맨 앞, 15행 안에 낮음은 없음
    sev = [x["severity"] for x in body["table"]]
    assert sev == sorted(sev, key=["심각", "높음", "보통", "낮음"].index)
    assert sev[:5] == ["심각"] * 5 and "낮음" not in sev
    text = report_text(data_dir, body["scan_id"])
    assert all(f"TEST-{i:04d}" in text for i in range(1, 21))  # 보고서에는 20건 모두


def test_table_max_rows_is_configurable(make_client):
    r = upload(make_client(FakeSource(many(6)), table_max_rows=2), content=b"flask==3.0.0\n")
    body = r.json()
    assert len(body["table"]) == 2 and body["table_omitted"] == 4


def test_case29_report_write_failure_is_a_warning(make_client, data_dir, monkeypatch):
    import app.storage as storage

    real_replace = os.replace

    def replace(src, dst):
        if os.path.basename(dst).startswith("vuln-report"):
            raise OSError("disk full")
        return real_replace(src, dst)

    monkeypatch.setattr(storage.os, "replace", replace)
    r = upload(make_client(FakeSource(SET_D)), content=FILE_D)
    body = r.json()
    assert r.status_code == 201
    assert "보고서 파일 저장 실패" in body["warnings"]
    assert len(body["table"]) == 3  # 표는 정상
    assert len(files_in(data_dir, "sbom")) == 1
    assert files_in(data_dir, "vuln-report") == []
    assert not list((data_dir / "demo").glob(".*"))  # 임시 파일도 남지 않음


def test_unpinned_only_makes_no_lookup(client, source):
    r = upload(client, content=b"flask>=2.0\nclick\n")
    assert r.status_code == 201 and source.calls == []
    assert r.json()["vulnerabilities_total"] == 0


def test_unknown_severity_goes_last_then_id_order(make_client):
    src = FakeSource({
        ("flask", "3.0.0"): [Finding("TEST-0012", None), Finding("TEST-0011", None),
                             Finding("TEST-0010", "높음")],
    })
    r = upload(make_client(src), content=b"flask==3.0.0\n")
    t = r.json()["table"]
    assert [x["vuln_id"] for x in t] == ["TEST-0010", "TEST-0011", "TEST-0012"]
    assert [x["severity"] for x in t] == ["높음", "알 수 없음", "알 수 없음"]


# ---- T2에서 이월한 "조회 호출" 판정 ----

def test_case8_lookup_calls(make_client):
    from .conftest import FILE_B
    src = FakeSource()
    upload(make_client(src), content=FILE_B)
    assert src.calls == [("requests", "2.31.0", "PyPI")]


@pytest.mark.parametrize("name", ["a b", ".hidden", "x" * 51, "..%2Fx"])
def test_case3_no_lookup_for_bad_names(client, source, name):
    assert upload(client, project=name).status_code == 400
    assert source.calls == []


def test_cases_4_5_6_7_no_lookup(make_client, source):
    c = make_client()
    assert c.post("/api/projects/demo/scans").status_code == 400
    assert upload(c, content=b"").status_code == 400
    assert upload(c, content=b"\xff\xfe\x80").status_code == 400
    assert upload(make_client(upload_max_bytes=10)).status_code == 413
    assert source.calls == []


def test_case12_no_lookup_when_save_fails(make_client, data_dir, source):
    data_dir.parent.mkdir(parents=True, exist_ok=True)
    data_dir.write_bytes(b"")
    assert upload(make_client()).status_code == 500
    assert source.calls == []


# ---- 심각도 변환 (4.5) ----

@pytest.mark.parametrize("text,expected", [
    ("CRITICAL", "심각"), ("HIGH", "높음"), ("MODERATE", "보통"), ("MEDIUM", "보통"),
    ("LOW", "낮음"), ("low", "낮음"), ("", None), (None, None), ("weird", None),
])
def test_text_severity(text, expected):
    assert from_text(text) == expected


@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.3),  # 5.215 -> 올림 5.3
    ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N", 5.6),  # 5.51 -> 올림 5.6
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 4.3),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3_scores(vector, score):
    assert cvss3_score(vector) == score


def test_severity_bands_and_unsupported_vectors():
    assert from_vectors(["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]) == "심각"
    assert from_vectors(["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"]) == "높음"  # 8.8
    assert from_vectors(["CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"]) == "보통"
    assert from_vectors(["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"]) == "보통"
    assert from_vectors(["CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"]) == "낮음"
    # v4는 계산하지 않음, 깨진 벡터도 None
    assert from_vectors(["CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"]) is None
    assert from_vectors(["garbage", "CVSS:3.1/AV:X"]) is None
    assert from_vectors([]) is None


# ---- OSV 응답 해석 (실제 응답 형식, 4.5) ----

def test_parse_record_prefers_text_severity():
    rec = {  # 실제 GHSA 응답 모양 (flask 3.0.0)
        "id": "GHSA-68rp-wp8r-4726",
        "database_specific": {"severity": "LOW"},
        "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"}],
    }
    assert parse_record(rec) == Finding("GHSA-68rp-wp8r-4726", "낮음")


def test_parse_record_falls_back_to_cvss3_vector():
    rec = {  # 실제 PYSEC 응답 모양: 문자열 등급 없음
        "id": "PYSEC-2026-1872",
        "database_specific": {},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"}],
    }
    assert parse_record(rec) == Finding("PYSEC-2026-1872", "보통")


def test_parse_record_without_severity_info():
    assert parse_record({"id": "X-1"}) == Finding("X-1", None)


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def _opener(pages, seen):
    it = iter(pages)

    def open_(req, timeout):
        seen.append((json.loads(req.data), timeout, req.full_url))
        return _Resp(json.dumps(next(it)).encode())

    return open_


def test_osv_source_follows_pages_and_dedups_ids():
    seen = []
    pages = [
        {"vulns": [{"id": "A-1", "database_specific": {"severity": "HIGH"}}],
         "next_page_token": "tok"},
        {"vulns": [{"id": "A-1"}, {"id": "A-2", "database_specific": {"severity": "LOW"}}]},
    ]
    src = OsvSource("https://osv.example/", 5, opener=_opener(pages, seen))
    got = src.query("flask", "3.0.0", "PyPI")
    assert got == [Finding("A-1", "높음"), Finding("A-2", "낮음")]
    assert seen[0][0] == {"package": {"name": "flask", "ecosystem": "PyPI"}, "version": "3.0.0"}
    assert seen[1][0]["page_token"] == "tok"
    assert seen[0][1] == 5 and seen[0][2] == "https://osv.example/v1/query"


def _requests_2_31_0_records():
    """실제 OSV 응답의 모양: 같은 취약점이 GHSA와 PYSEC로 이중 등록되어 있음."""
    return [
        {"id": "GHSA-9hjg-9r4m-mvj7", "aliases": ["CVE-2024-47081", "PYSEC-2026-1872"],
         "database_specific": {"severity": "MODERATE"}},
        {"id": "PYSEC-2026-1872", "aliases": ["CVE-2024-47081", "GHSA-9hjg-9r4m-mvj7"],
         "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"}]},
        {"id": "GHSA-9wx4-h78v-vm56", "aliases": ["CVE-2024-35195", "PYSEC-2026-1873"],
         "database_specific": {"severity": "MODERATE"}},
        {"id": "PYSEC-2026-1873", "aliases": ["CVE-2024-35195", "GHSA-9wx4-h78v-vm56"]},
    ]


def test_osv_source_merges_aliased_records_into_one_finding():
    src = OsvSource("https://osv.example", 5,
                    opener=_opener([{"vulns": _requests_2_31_0_records()}], []))
    got = src.query("requests", "2.31.0", "PyPI")
    assert got == [Finding("CVE-2024-47081", "보통"), Finding("CVE-2024-35195", "보통")]


def test_merge_keeps_highest_severity_of_merged_records():
    recs = [
        {"id": "GHSA-aaaa", "aliases": ["CVE-1"], "database_specific": {"severity": "LOW"}},
        {"id": "PYSEC-1", "aliases": ["CVE-1"],
         "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
    ]
    from app.osv import merge_aliases
    assert merge_aliases(recs) == [Finding("CVE-1", "심각")]


def test_merge_display_id_without_cve_prefers_ghsa_and_unrelated_stay_separate():
    from app.osv import merge_aliases
    recs = [
        {"id": "PYSEC-2", "aliases": ["GHSA-bbbb"]},
        {"id": "GHSA-bbbb", "aliases": ["PYSEC-2"], "database_specific": {"severity": "HIGH"}},
        {"id": "OSV-9"},
    ]
    assert merge_aliases(recs) == [Finding("GHSA-bbbb", "높음"), Finding("OSV-9", None)]


def test_merge_chain_of_aliases_joins_into_one():
    from app.osv import merge_aliases
    recs = [{"id": "A", "aliases": ["B"]}, {"id": "C", "aliases": ["D"]},
            {"id": "E", "aliases": ["B", "D"]}]
    assert len(merge_aliases(recs)) == 1


def test_osv_source_empty_response_means_no_vulns():
    src = OsvSource("https://osv.example", 5, opener=_opener([{}], []))
    assert src.query("click", "8.1.7", "PyPI") == []


@pytest.mark.parametrize("exc", [OSError("down"), TimeoutError(), ValueError("bad")])
def test_osv_source_failures_become_lookup_failed(exc):
    def open_(req, timeout):
        raise exc

    with pytest.raises(LookupFailed):
        OsvSource("https://osv.example", 5, opener=open_).query("a", "1", "PyPI")


def test_osv_source_non_object_or_malformed_response():
    with pytest.raises(LookupFailed):
        OsvSource("https://osv.example", 5, opener=_opener([[1, 2]], [])).query("a", "1", "PyPI")
    with pytest.raises(LookupFailed):
        OsvSource("https://osv.example", 5, opener=_opener([{"vulns": [{}]}], [])).query("a", "1", "PyPI")


# ---- 사례 25: 실제 OSV 1회 확인 (네트워크 필요, 기본은 건너뜀) ----

@pytest.mark.skipif(os.environ.get("OSV_LIVE_TEST") != "1", reason="OSV_LIVE_TEST=1일 때만 실제 OSV 호출")
def test_case25_real_osv(data_dir):
    from fastapi.testclient import TestClient
    from app.config import Settings
    from app.main import create_app

    c = TestClient(create_app(Settings(data_dir=data_dir)))  # 실제 OsvSource
    r = upload(c, content=b"requests==2.31.0\n")  # 구현 때 확인한 취약 버전
    assert r.status_code == 201
    assert r.json()["vulnerabilities_total"] >= 1
