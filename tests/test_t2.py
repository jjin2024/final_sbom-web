"""T2 확인 사례 2~9, 11, 12 (3.2).

"조회 호출 0회/N회" 판정은 취약점 조회 분리 부분이 생기는 T3에서 추가한다
(T2에는 조회가 없어서 호출 기록을 남길 곳이 없음).
"""
import pytest

from .conftest import (
    FILE_A, FILE_B, FILE_C_COMMENT, FILE_C_EMPTY, FILE_D, FILE_H, FILE_I, upload,
)


def sbom_lines(data_dir, project="demo"):
    files = list((data_dir / project).glob("sbom-*.txt"))
    assert len(files) == 1
    return files[0].read_text(encoding="utf-8").splitlines()


def entries(lines):
    """목록 항목 줄만. 헤더(#)와 끝의 "이전 실행 대비" 구역(##부터)은 뺀다."""
    out = []
    for l in lines:
        if l.startswith("##"):
            break
        if not l.startswith("#"):
            out.append(l)
    return out


def test_case2_filename_not_checked(client, data_dir):
    r = upload(client, filename="my-deps.txt")
    assert r.status_code == 201 and r.json()["collected"] == 2
    lines = sbom_lines(data_dir)
    assert "flask 3.0.0 PyPI" in lines and "requests 2.31.0 PyPI" in lines


@pytest.mark.parametrize(
    "name", ["a b", ".hidden", "x" * 51, "..%2Fx", "%2E%2E%2Fx", "..%5Cx", "-x", "_x"]
)
def test_case3_bad_project_name(client, data_dir, name):
    r = upload(client, project=name)
    assert r.status_code == 400
    assert "프로젝트 이름 규칙" in r.json()["error"]
    assert not data_dir.exists() or not any(data_dir.iterdir())


@pytest.mark.parametrize("name", ["demo", "a", "x" * 50, "p1.v2_x-y", "7up"])
def test_valid_project_names(client, name):
    assert upload(client, project=name).status_code == 201


def test_case4_no_file(client, data_dir):
    r = client.post("/api/projects/demo/scans")
    assert r.status_code == 400 and "파일 없음" in r.json()["error"]
    r = client.post("/api/projects/demo/scans", data={"file": "not-a-file"})
    assert r.status_code == 400 and "파일 없음" in r.json()["error"]
    assert not data_dir.exists()


@pytest.mark.parametrize("content", [FILE_C_EMPTY, FILE_C_COMMENT])
def test_case5_no_packages_keeps_history(client, data_dir, content):
    assert upload(client).status_code == 201
    snapshot = lambda: sorted((x.name, x.read_bytes()) for x in (data_dir / "demo").iterdir())
    before = snapshot()

    r = upload(client, content=content)
    assert r.status_code == 400 and "패키지를 찾을 수 없음" in r.json()["error"]
    assert snapshot() == before  # 새 파일 없음, 기존 파일 내용 그대로


def test_all_unparseable_lines_is_zero_packages(client, data_dir):
    r = upload(client, content=b"-r other.txt\ngit+https://github.com/x/y.git\n")
    assert r.status_code == 400 and "패키지를 찾을 수 없음" in r.json()["error"]
    assert not data_dir.exists()


def test_case6_size_limit(make_client, data_dir):
    assert len(FILE_A) == 30
    r = upload(make_client(upload_max_bytes=10))
    assert r.status_code == 413 and "10" in r.json()["error"]
    assert not data_dir.exists()


def test_size_limit_boundary(make_client):
    c = make_client(upload_max_bytes=len(FILE_A))
    assert upload(c).status_code == 201  # 상한과 같으면 통과
    c = make_client(upload_max_bytes=len(FILE_A) - 1)
    assert upload(c, project="other").status_code == 413


def test_case7_binary_file(client, data_dir):
    r = upload(client, content=b"\xff\xfe\x00\x01\x80\x81")
    assert r.status_code == 400 and "텍스트 파일이 아님" in r.json()["error"]
    assert not data_dir.exists()


def test_case8_ranges_and_missing_version(client, data_dir):
    r = upload(client, content=FILE_B)
    assert r.status_code == 201
    body = r.json()
    assert body["collected"] == 3 and body["not_looked_up"] == 2
    lines = sbom_lines(data_dir)
    assert "flask >=2.0 PyPI (확정 버전 아님)" in lines
    assert "requests 2.31.0 PyPI" in lines
    assert "click - PyPI (확정 버전 아님)" in lines


@pytest.mark.parametrize(
    "line,expected",
    [
        ("flask~=1.4", "flask ~=1.4 PyPI (확정 버전 아님)"),
        ("flask>=2.0,<3", "flask >=2.0,<3 PyPI (확정 버전 아님)"),
        ("flask >= 2.0", "flask >=2.0 PyPI (확정 버전 아님)"),
        ("flask==2.*", "flask ==2.* PyPI (확정 버전 아님)"),
        ("flask == 3.0.0  # pin", "flask 3.0.0 PyPI"),
        ("flask==3.0.0; python_version>'3.8'", "flask 3.0.0 PyPI"),
    ],
)
def test_version_notations(client, data_dir, line, expected):
    r = upload(client, content=line.encode())
    assert r.status_code == 201
    assert expected in sbom_lines(data_dir)


def test_case9_skipped_lines(client, data_dir):
    r = upload(client, content=FILE_H)
    assert r.status_code == 201
    body = r.json()
    assert body["skipped_lines"] == 2 and body["collected"] == 2
    assert entries(sbom_lines(data_dir)) == ["flask 3.0.0 PyPI", "requests 2.31.0 PyPI"]


def test_duplicate_lines_recorded_per_line(client, data_dir):
    r = upload(client, content=FILE_I)
    assert r.json()["collected"] == 3
    assert sbom_lines(data_dir).count("flask 3.0.0 PyPI") == 2


def test_utf8_bom_is_accepted(client):
    r = upload(client, content=b"\xef\xbb\xbfflask==3.0.0\n")
    assert r.status_code == 201 and r.json()["collected"] == 1


def test_case11_projects_are_separate(client, data_dir):
    upload(client, project="p1", content=FILE_A)
    upload(client, project="p2", content=FILE_D)
    assert entries(sbom_lines(data_dir, "p1")) == ["flask 3.0.0 PyPI", "requests 2.31.0 PyPI"]
    assert len(entries(sbom_lines(data_dir, "p2"))) == 4
    assert {p.name for p in data_dir.iterdir()} == {"p1", "p2"}


def test_case12_unwritable_data_dir(make_client, data_dir):
    # 읽기 전용 폴더를 흉내: 데이터 폴더 자리에 파일이 있어 하위 폴더를 만들 수 없음
    data_dir.parent.mkdir(parents=True, exist_ok=True)
    data_dir.write_bytes(b"")
    r = upload(make_client())
    assert r.status_code == 500 and "저장 실패" in r.json()["error"]
    assert data_dir.is_file()  # 아무것도 새로 만들어지지 않음


def test_case12_write_failure_leaves_no_partial_file(client, data_dir, monkeypatch):
    import app.storage as storage

    def boom(src, dst):
        raise OSError("disk full")

    # 목록 파일은 os.link(덮어쓰지 않고 만들기), 지원하지 않는 파일 시스템에서는 os.replace로 저장한다
    monkeypatch.setattr(storage.os, "link", boom)
    monkeypatch.setattr(storage.os, "replace", boom)
    r = upload(client)
    assert r.status_code == 500 and "저장 실패" in r.json()["error"]
    assert not list(data_dir.rglob("*")) if data_dir.exists() else True


def test_error_response_has_no_internal_details(make_client, data_dir):
    data_dir.parent.mkdir(parents=True, exist_ok=True)
    data_dir.write_bytes(b"")
    text = upload(make_client()).text
    assert str(data_dir) not in text and "Traceback" not in text
