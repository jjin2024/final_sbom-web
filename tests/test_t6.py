"""T6 확인 사례 30 (3.2): 조회 실패 처리 (R3-3)."""
import hashlib

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.osv import OsvSource

from .conftest import FILE_A, FILE_D, upload
from .fakes import SET_D, FakeSource

OLD_REPORT = "vuln-report-20261101-090000.txt"
OLD_CONTENT = "# 취약점 보고서\n# 이전 요청의 보고서\nTEST-9999 flask 3.0.0 높음\n"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_case30_lookup_failure_returns_502_and_keeps_list(make_client, data_dir):
    folder = data_dir / "demo"
    folder.mkdir(parents=True)
    old = folder / OLD_REPORT
    old.write_text(OLD_CONTENT, encoding="utf-8")
    before = digest(old)

    src = FakeSource(SET_D, fail=True)  # 취약점 DB 연결 차단
    r = upload(make_client(src), content=FILE_D)

    assert r.status_code == 502
    body = r.json()
    assert "조회 실패, 목록은 저장됨" in body["error"]
    scan = body["scan_id"]

    # 새 목록은 저장됨, 새 보고서는 없음, 이전 보고서는 그대로
    sbom = folder / f"sbom-{scan}.txt"
    assert sbom.exists()
    assert "flask 3.0.0 PyPI" in sbom.read_text(encoding="utf-8")
    assert not (folder / f"vuln-report-{scan}.txt").exists()
    assert sorted(p.name for p in folder.glob("vuln-report-*.txt")) == [OLD_REPORT]
    assert digest(old) == before
    assert not list(folder.glob(".*"))  # 임시 파일도 남지 않음
    # 요약(Gemini) 호출 0회는 요약이 생기는 T8에서 판정한다


def test_failure_on_a_later_package_still_fails_the_whole_request(make_client, data_dir):
    src = FakeSource(SET_D, fail_for={("django", "4.2.0")})  # 앞의 두 패키지는 성공
    r = upload(make_client(src), content=FILE_D)
    assert r.status_code == 502
    assert len(src.calls) == 3  # flask, requests는 성공, django에서 중단
    assert not list((data_dir / "demo").glob("vuln-report-*.txt"))
    assert len(list((data_dir / "demo").glob("sbom-*.txt"))) == 1


def test_502_does_not_leak_internal_details(make_client):
    text = upload(make_client(FakeSource(fail=True)), content=FILE_A).text
    assert "secret-host" not in text and "blocked" not in text
    assert "Traceback" not in text


def test_real_osv_source_timeout_becomes_502(data_dir):
    def opener(req, timeout):
        raise TimeoutError()

    c = TestClient(create_app(
        Settings(data_dir=data_dir),
        vuln_source=OsvSource("https://osv.example", 1, opener=opener),
    ))
    r = upload(c, content=FILE_A)
    assert r.status_code == 502 and "조회 실패, 목록은 저장됨" in r.json()["error"]


def test_next_request_after_failure_works_normally(make_client, data_dir):
    failing = FakeSource(fail=True)
    assert upload(make_client(failing), content=FILE_A).status_code == 502
    import time
    time.sleep(1.1)  # 같은 시각(초) 충돌(T7)과 무관하게 새 시각으로 요청
    ok = upload(make_client(FakeSource(SET_D)), content=FILE_D)
    assert ok.status_code == 201 and ok.json()["vulnerabilities_total"] == 3


def test_no_lookup_when_nothing_is_pinned_so_no_502(make_client):
    src = FakeSource(fail=True)
    r = upload(make_client(src), content=b"flask>=2.0\nclick\n")
    assert r.status_code == 201 and src.calls == []
