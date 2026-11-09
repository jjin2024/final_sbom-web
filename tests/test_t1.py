"""T1 확인 사례 1, 10 (3.2)."""
import re
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

from .conftest import upload


def test_case1_upload_A_saves_list(client, data_dir):
    r = upload(client)
    assert r.status_code == 201
    body = r.json()
    assert re.fullmatch(r"\d{8}-\d{6}", body["scan_id"])
    assert body["collected"] == 2

    # 같은 시각의 목록 1개 + 보고서 1개 (사례 1, 보고서는 T3부터)
    files = sorted((data_dir / "demo").iterdir())
    assert [f.name for f in files] == [
        f"sbom-{body['scan_id']}.txt",
        f"vuln-report-{body['scan_id']}.txt",
    ]
    lines = files[0].read_text(encoding="utf-8").splitlines()
    assert "flask 3.0.0 PyPI" in lines
    assert "requests 2.31.0 PyPI" in lines
    # 업로드한 원본은 /data에 저장되지 않음
    assert not list(data_dir.rglob("requirements.txt"))


def test_case10_filename_is_kst_and_header(client, data_dir, monkeypatch):
    # 서버 시간대가 UTC인 상황: 프로세스 시간대와 무관하게 KST로 계산해야 한다
    monkeypatch.setenv("TZ", "UTC")
    kst = timezone(timedelta(hours=9))
    before = datetime.now(kst).replace(microsecond=0)
    r = upload(client)
    after = datetime.now(kst)
    assert r.status_code == 201

    files = list((data_dir / "demo").glob("sbom-*.txt"))
    assert len(files) == 1
    m = re.fullmatch(r"sbom-(\d{8}-\d{6})\.txt", files[0].name)
    assert m
    stamp = datetime.strptime(m.group(1), "%Y%m%d-%H%M%S").replace(tzinfo=kst)
    assert before - timedelta(minutes=1) <= stamp <= after + timedelta(minutes=1)

    lines = files[0].read_text(encoding="utf-8").splitlines()
    assert lines[0] == "# SBOM 목록"
    assert lines[1] == "# 프로젝트: demo"
    assert lines[2].startswith("# 실행 시각: ") and lines[2].endswith(" KST")


def test_filename_uses_injected_kst_time_regardless_of_utc(data_dir):
    # UTC 2026-11-09 02:30:05 == KST 11:30:05 (2.4의 예시)
    fixed = datetime(2026, 11, 9, 2, 30, 5, tzinfo=timezone.utc)
    c = TestClient(create_app(Settings(data_dir=data_dir), clock=lambda: fixed))
    r = upload(c)
    assert r.json()["scan_id"] == "20261109-113005"
    f = data_dir / "demo" / "sbom-20261109-113005.txt"
    assert "# 실행 시각: 2026-11-09 11:30:05 KST" in f.read_text(encoding="utf-8")
