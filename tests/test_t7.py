"""T7 확인 사례 13~22 (3.2): 이력 조회(R2-2), 재요청(R2-3), 이전 실행 대비(R2-4)."""
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from .conftest import FILE_A, FILE_D, upload
from .fakes import SET_D, FakeSource

KST = timezone(timedelta(hours=9))


def at(*args):
    """요청 시각을 KST로 고정하는 clock (3.1의 "고정 시각")."""
    return lambda: datetime(*args, tzinfo=KST)


def scan(make_client, when, content=FILE_A, project="demo", source=None):
    return upload(make_client(vuln_source=source, clock=at(*when)), project=project, content=content)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def comparison_section(sbom_text):
    lines = sbom_text.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("## 이전 실행 대비"))
    return lines[start:]


# ---- R2-2 이력 조회 ----

def test_case13_history_is_newest_first(make_client, client):
    scan(make_client, (2026, 11, 1, 9, 0, 0))
    scan(make_client, (2026, 11, 5, 14, 30, 5))
    scan(make_client, (2026, 11, 3, 8, 15, 0), source=FakeSource(fail=True))  # 502: 목록만 있음
    r = client.get("/api/projects/demo/scans")
    assert r.status_code == 200
    body = r.json()
    assert body["project"] == "demo"
    got = [(s["scan_id"], s["time"], s["has_report"]) for s in body["scans"]]
    assert got == [
        ("20261105-143005", "2026-11-05 14:30:05 KST", True),
        ("20261103-081500", "2026-11-03 08:15:00 KST", False),
        ("20261101-090000", "2026-11-01 09:00:00 KST", True),
    ]
    assert body["scans"][0]["links"] == {
        "sbom": "/api/projects/demo/scans/20261105-143005/sbom",
        "report": "/api/projects/demo/scans/20261105-143005/report",
    }
    assert body["scans"][1]["links"]["report"] is None


def test_case14_no_history_and_unknown_scan(make_client, client):
    scan(make_client, (2026, 11, 1, 9, 0, 0))
    r = client.get("/api/projects/none/scans")
    assert r.status_code == 200 and r.json() == {"project": "none", "scans": []}
    assert client.get("/api/projects/demo/scans/20260101-000000/sbom").status_code == 404
    assert client.get("/api/projects/demo/scans/20260101-000000/report").status_code == 404


@pytest.mark.parametrize("sid", ["abc", "2026", "..%2F..%2Fetc%2Fpasswd", "20261101-09000", "20261101-090000.txt"])
def test_scan_id_with_wrong_format_is_404_not_a_file_read(make_client, client, sid):
    scan(make_client, (2026, 11, 1, 9, 0, 0))
    assert client.get(f"/api/projects/demo/scans/{sid}/sbom").status_code == 404


@pytest.mark.parametrize("name", ["a b", ".hidden", "x" * 51, "..%2Fx"])
def test_history_routes_reject_bad_project_names_with_400(client, name):
    assert client.get(f"/api/projects/{name}/scans").status_code == 400
    assert client.get(f"/api/projects/{name}/scans/20261101-090000/sbom").status_code == 400
    assert client.get(f"/api/projects/{name}/scans/20261101-090000/report").status_code == 400


def test_case15_download_matches_stored_files(make_client, client, data_dir):
    ok = scan(make_client, (2026, 11, 1, 9, 0, 0), content=FILE_D, source=FakeSource(SET_D)).json()
    failed = scan(make_client, (2026, 11, 2, 9, 0, 0), content=FILE_D, source=FakeSource(fail=True)).json()
    assert failed["scan_id"] == "20261102-090000"

    folder = data_dir / "demo"
    r = client.get(f"/api/projects/demo/scans/{ok['scan_id']}/sbom")
    assert r.status_code == 200 and r.text == (folder / f"sbom-{ok['scan_id']}.txt").read_text(encoding="utf-8")
    assert "attachment" in r.headers["content-disposition"]
    r = client.get(f"/api/projects/demo/scans/{ok['scan_id']}/report")
    assert r.status_code == 200 and r.text == (folder / f"vuln-report-{ok['scan_id']}.txt").read_text(encoding="utf-8")
    assert "TEST-0001" in r.text
    # 조회 실패로 보고서가 없는 스캔: 목록은 200, 보고서는 404
    assert client.get("/api/projects/demo/scans/20261102-090000/sbom").status_code == 200
    assert client.get("/api/projects/demo/scans/20261102-090000/report").status_code == 404


def test_download_links_in_scan_response_work(make_client, client):
    r = scan(make_client, (2026, 11, 1, 9, 0, 0), source=FakeSource(SET_D))
    links = r.json()["links"]
    assert links["sbom"] == "/api/projects/demo/scans/20261101-090000/sbom"
    assert client.get(links["sbom"]).status_code == 200
    assert client.get(links["report"]).status_code == 200


def test_links_have_no_report_link_when_report_was_not_saved(make_client, monkeypatch):
    import os
    import app.storage as storage
    real = os.replace

    def replace(src, dst):
        if os.path.basename(dst).startswith("vuln-report"):
            raise OSError("disk full")
        return real(src, dst)

    monkeypatch.setattr(storage.os, "replace", replace)
    body = scan(make_client, (2026, 11, 1, 9, 0, 0)).json()
    assert body["links"]["report"] is None and body["links"]["sbom"]


# ---- R2-3 재요청 ----

def test_case16_rerequest_makes_new_files_and_keeps_old(make_client, data_dir):
    scan(make_client, (2026, 11, 9, 10, 0, 0))
    first = data_dir / "demo" / "sbom-20261109-100000.txt"
    before = sha(first)
    r = scan(make_client, (2026, 11, 9, 10, 0, 3))
    assert r.status_code == 201
    assert sorted(p.name for p in (data_dir / "demo").glob("sbom-*.txt")) == [
        "sbom-20261109-100000.txt", "sbom-20261109-100003.txt"]
    assert sha(first) == before  # 첫 번째 스캔의 파일은 요청 전과 같음


def test_case17_same_second_is_rejected_with_409(make_client, data_dir):
    src = FakeSource(SET_D)
    first = scan(make_client, (2026, 11, 9, 10, 0, 0), content=FILE_D, source=src)
    assert first.status_code == 201
    folder = data_dir / "demo"
    snapshot = sorted((p.name, sha(p)) for p in folder.iterdir())
    calls_after_first = len(src.calls)

    second = scan(make_client, (2026, 11, 9, 10, 0, 0), content=FILE_A, source=src)
    assert second.status_code == 409
    assert "같은 시각의 스캔이 있음" in second.json()["error"]
    assert sorted((p.name, sha(p)) for p in folder.iterdir()) == snapshot  # 첫 요청 결과 그대로
    assert len(src.calls) == calls_after_first  # 두 번째 요청의 조회 호출 0회


def test_same_second_conflict_when_only_the_report_exists(make_client, data_dir):
    folder = data_dir / "demo"
    folder.mkdir(parents=True)
    (folder / "vuln-report-20261109-100000.txt").write_text("old", encoding="utf-8")
    assert scan(make_client, (2026, 11, 9, 10, 0, 0)).status_code == 409
    assert (folder / "vuln-report-20261109-100000.txt").read_text(encoding="utf-8") == "old"
    assert not list(folder.glob("sbom-*.txt"))


def test_conflict_when_the_file_appears_between_check_and_save(make_client, data_dir, monkeypatch):
    # 동시 요청: 확인 뒤 저장 사이에 같은 이름의 파일이 생겨도 덮어쓰지 않는다 (os.link가 거절)
    import os
    import app.storage as storage
    real_link = os.link

    def racing_link(src, dst):
        open(dst, "w", encoding="utf-8").write("winner")
        return real_link(src, dst)

    monkeypatch.setattr(storage.os, "link", racing_link)
    r = scan(make_client, (2026, 11, 9, 10, 0, 0))
    assert r.status_code == 409
    assert (data_dir / "demo" / "sbom-20261109-100000.txt").read_text(encoding="utf-8") == "winner"
    assert not list((data_dir / "demo").glob(".*"))  # 임시 파일 정리


def test_save_falls_back_when_hard_links_are_unsupported(make_client, data_dir, monkeypatch):
    import os
    import app.storage as storage

    def no_link(src, dst):
        raise OSError("hard links not supported")

    monkeypatch.setattr(storage.os, "link", no_link)
    assert scan(make_client, (2026, 11, 9, 10, 0, 0)).status_code == 201
    assert scan(make_client, (2026, 11, 9, 10, 0, 0)).status_code == 409  # 대체 경로에서도 덮어쓰지 않음
    assert len(list((data_dir / "demo").glob("sbom-*.txt"))) == 1


# ---- R2-4 이전 실행 대비 ----

def test_case18_first_request_has_no_baseline(make_client, data_dir):
    r = scan(make_client, (2026, 11, 9, 10, 0, 0))
    assert r.status_code == 201
    c = r.json()["comparison"]
    assert c["status"] == "비교 대상 없음" and c["lines"] == ["## 이전 실행 대비", "비교 대상 없음"]
    text = (data_dir / "demo" / "sbom-20261109-100000.txt").read_text(encoding="utf-8")
    assert comparison_section(text) == ["## 이전 실행 대비", "비교 대상 없음"]
    assert r.json()["vulnerabilities_total"] == 0  # 이후 단계는 정상 진행
    assert (data_dir / "demo" / "vuln-report-20261109-100000.txt").exists()


def test_case19_added_removed_changed(make_client, data_dir):
    scan(make_client, (2026, 11, 9, 10, 0, 0), content=FILE_A)
    changed_file = b"flask==3.0.1\nclick==8.1.7\n"  # requests 줄 삭제
    r = scan(make_client, (2026, 11, 9, 11, 0, 0), content=changed_file)
    c = r.json()["comparison"]
    assert c["status"] == "비교함" and c["previous_scan_id"] == "20261109-100000"
    assert [(i["name"], i["version"]) for i in c["added"]] == [("click", "8.1.7")]
    assert [(i["name"], i["version"]) for i in c["removed"]] == [("requests", "2.31.0")]
    assert c["changed"] == [{"name": "flask", "from": "3.0.0", "to": "3.0.1", "ecosystem": "PyPI"}]
    assert c["unchanged"] == 0
    expected = [
        "## 이전 실행 대비 (직전: sbom-20261109-100000.txt)",
        "추가 1: click 8.1.7 PyPI",
        "삭제 1: requests 2.31.0 PyPI",
        "변경 1: flask 3.0.0 -> 3.0.1 PyPI",
        "변경 없음 0",
    ]
    assert c["lines"] == expected  # 응답과 파일의 내용이 같음
    text = (data_dir / "demo" / "sbom-20261109-110000.txt").read_text(encoding="utf-8")
    assert comparison_section(text) == expected


def test_case20_same_file_again_is_all_unchanged_and_still_looks_up(make_client):
    src = FakeSource()
    scan(make_client, (2026, 11, 9, 10, 0, 0), source=src)
    r = scan(make_client, (2026, 11, 9, 10, 0, 5), source=src)
    c = r.json()["comparison"]
    assert (len(c["added"]), len(c["removed"]), len(c["changed"]), c["unchanged"]) == (0, 0, 0, 2)
    assert c["lines"][1:] == ["추가 0", "삭제 0", "변경 0", "변경 없음 2"]
    assert len(src.calls) == 4  # 두 요청 모두 각 2회: 변경이 없어도 매번 다시 조회


def test_case21_other_projects_are_not_compared(make_client):
    scan(make_client, (2026, 11, 9, 10, 0, 0), project="p1")
    r = scan(make_client, (2026, 11, 9, 11, 0, 0), project="p2")
    assert r.json()["comparison"]["status"] == "비교 대상 없음"


def test_case22_unreadable_previous_skips_only_the_comparison(make_client, data_dir):
    folder = data_dir / "demo"
    folder.mkdir(parents=True)
    (folder / "sbom-20261109-090000.txt").write_bytes(b"")  # 빈 파일
    src = FakeSource(SET_D)
    r = scan(make_client, (2026, 11, 9, 10, 0, 0), content=FILE_D, source=src)
    assert r.status_code == 201
    c = r.json()["comparison"]
    assert c["status"] == "비교 건너뜀" and c["message"] == "비교 건너뜀(직전 파일을 읽을 수 없음)"
    assert c["lines"][1] == "비교 건너뜀(직전 파일을 읽을 수 없음)"
    assert (folder / "sbom-20261109-100000.txt").exists()  # 새 목록 저장
    assert r.json()["vulnerabilities_total"] == 3 and src.calls  # 조회도 정상 진행


@pytest.mark.parametrize("content", [
    b"not a sbom file\n",
    b"# SBOM list\nflask 3.0.0 PyPI\n",            # 헤더가 다름
    b"# SBOM \xeb\xaa\xa9\xeb\xa1\x9d\nflask 3.0.0\n",  # 줄 형식이 다름
    b"\xff\xfe\x00\x01",                              # 텍스트가 아님
    "# SBOM 목록\n# 프로젝트: demo\n".encode(),        # 항목이 없음
])
def test_unreadable_previous_variants(make_client, data_dir, content):
    folder = data_dir / "demo"
    folder.mkdir(parents=True)
    (folder / "sbom-20261109-090000.txt").write_bytes(content)
    r = scan(make_client, (2026, 11, 9, 10, 0, 0))
    assert r.status_code == 201 and r.json()["comparison"]["status"] == "비교 건너뜀"


def test_previous_is_the_latest_earlier_scan_not_a_later_one(make_client):
    scan(make_client, (2026, 11, 9, 10, 0, 0), content=b"flask==1.0\n")
    scan(make_client, (2026, 11, 9, 12, 0, 0), content=b"flask==3.0\n")
    r = scan(make_client, (2026, 11, 9, 11, 0, 0), content=b"flask==2.0\n")  # 사이에 끼어든 요청
    c = r.json()["comparison"]
    assert c["previous_scan_id"] == "20261109-100000"
    assert c["changed"] == [{"name": "flask", "from": "1.0", "to": "2.0", "ecosystem": "PyPI"}]


def test_range_notation_change_counts_as_version_change(make_client):
    scan(make_client, (2026, 11, 9, 10, 0, 0), content=b"flask>=2.0\nclick\nrequests>=1.0\n")
    r = scan(make_client, (2026, 11, 9, 11, 0, 0), content=b"flask>=2.1\nclick\nrequests==1.0\n")
    c = r.json()["comparison"]
    assert {(i["name"], i["from"], i["to"]) for i in c["changed"]} == {
        ("flask", ">=2.0", ">=2.1"), ("requests", ">=1.0", "1.0")}
    assert c["unchanged"] == 1  # click: 버전 없음(-)이 그대로


def test_previous_with_comparison_section_is_parsed_correctly(make_client):
    scan(make_client, (2026, 11, 9, 10, 0, 0), content=b"flask==1.0\n")
    scan(make_client, (2026, 11, 9, 11, 0, 0), content=b"flask==2.0\nclick==8.0\n")  # 구역이 있는 파일
    r = scan(make_client, (2026, 11, 9, 12, 0, 0), content=b"flask==2.0\nclick==8.0\n")
    c = r.json()["comparison"]
    assert c["status"] == "비교함" and c["unchanged"] == 2 and not c["added"]


def test_failed_lookup_scan_can_still_be_the_baseline(make_client):
    scan(make_client, (2026, 11, 9, 10, 0, 0), content=FILE_A, source=FakeSource(fail=True))  # 502
    r = scan(make_client, (2026, 11, 9, 11, 0, 0), content=FILE_A)
    assert r.json()["comparison"]["unchanged"] == 2


def test_duplicate_lines_in_one_file_count_once(make_client):
    scan(make_client, (2026, 11, 9, 10, 0, 0), content=b"flask==3.0.0\nflask==3.0.0\nrequests==2.31.0\n")
    r = scan(make_client, (2026, 11, 9, 11, 0, 0), content=b"flask==3.0.0\nrequests==2.31.0\n")
    assert r.json()["comparison"]["unchanged"] == 2


def test_case41_history_and_comparison_survive_a_new_server_instance(make_client, data_dir):
    # 서버(컨테이너)를 새로 띄워도 volume의 파일에서 이력과 직전 목록을 읽는다
    scan(make_client, (2026, 11, 9, 10, 0, 0), content=FILE_A)
    new_server = make_client(clock=at(2026, 11, 9, 11, 0, 0))
    assert [s["scan_id"] for s in new_server.get("/api/projects/demo/scans").json()["scans"]] == ["20261109-100000"]
    r = upload(new_server, content=b"flask==3.0.1\nrequests==2.31.0\n")
    assert r.json()["comparison"]["changed"][0]["to"] == "3.0.1"
