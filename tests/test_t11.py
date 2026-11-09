"""T11: CycloneDX 1.5 JSON 출력 (R2-5)."""
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from app import cyclonedx
from app.parser import ECO_CRATES, ECO_GO, ECO_NPM, ECO_PYPI, Package, parse_requirements
from app.storage import list_scans, previous_scan_id

from .conftest import FILE_A, FILE_B, FILE_I, upload
from .fakes import SET_D, FakeSource

SCHEMAS = Path(__file__).parent / "schemas"
KST = timezone(timedelta(hours=9))


def _load(name):
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


def _validator():
    """CycloneDX 1.5 공식 JSON 스키마(tests/schemas/, Apache-2.0)로 검증한다."""
    registry = Registry().with_resources([
        ("http://cyclonedx.org/schema/spdx.schema.json",
         Resource.from_contents(_load("spdx.schema.json"), default_specification=DRAFT7)),
        ("http://cyclonedx.org/schema/jsf-0.82.schema.json",
         Resource.from_contents(_load("jsf-0.82.schema.json"), default_specification=DRAFT7)),
    ])
    return jsonschema.Draft7Validator(_load("bom-1.5.schema.json"), registry=registry)


def assert_valid(doc):
    errors = sorted(_validator().iter_errors(doc), key=lambda e: list(e.path))
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors[:3]]


def cdx_path(data_dir, scan, project="demo"):
    return data_dir / project / f"sbom-{scan}.cdx.json"


def read_cdx(data_dir, body, project="demo"):
    return json.loads(cdx_path(data_dir, body["scan_id"], project).read_text(encoding="utf-8"))


# ---- 사례: 파일 A, B, I ----

def test_file_A_creates_cyclonedx_with_same_scan_id(client, data_dir):
    body = upload(client).json()
    sid = body["scan_id"]
    txt = data_dir / "demo" / f"sbom-{sid}.txt"
    assert txt.exists() and cdx_path(data_dir, sid).exists()  # 시각이 목록 파일과 같다
    doc = read_cdx(data_dir, body)
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5" and doc["version"] == 1
    assert [c["purl"] for c in doc["components"]] == ["pkg:pypi/flask@3.0.0", "pkg:pypi/requests@2.31.0"]
    assert all(c["type"] == "library" and c["bom-ref"] == c["purl"] for c in doc["components"])
    assert [c["version"] for c in doc["components"]] == ["3.0.0", "2.31.0"]
    assert_valid(doc)
    # 기존 목록 파일의 형식은 그대로
    lines = txt.read_text(encoding="utf-8").splitlines()
    assert "flask 3.0.0 PyPI" in lines and "requests 2.31.0 PyPI" in lines


def test_file_B_unpinned_items_have_no_version_but_keep_the_original_spec(client, data_dir):
    body = upload(client, content=FILE_B).json()
    doc = read_cdx(data_dir, body)
    by_name = {c["name"]: c for c in doc["components"]}
    assert "version" not in by_name["flask"] and by_name["flask"]["purl"] == "pkg:pypi/flask"
    assert by_name["flask"]["properties"] == [{"name": "sbom-web:version-spec", "value": ">=2.0"}]
    assert "version" not in by_name["click"] and by_name["click"]["purl"] == "pkg:pypi/click"
    assert by_name["click"]["properties"] == [{"name": "sbom-web:version-spec", "value": "-"}]
    assert by_name["requests"]["version"] == "2.31.0" and "properties" not in by_name["requests"]
    assert by_name["requests"]["purl"] == "pkg:pypi/requests@2.31.0"
    assert_valid(doc)


def test_file_I_duplicate_lines_become_one_component_but_list_keeps_three_lines(client, data_dir):
    body = upload(client, content=FILE_I).json()
    assert body["collected"] == 3
    doc = read_cdx(data_dir, body)
    assert [c["purl"] for c in doc["components"]] == ["pkg:pypi/flask@3.0.0", "pkg:pypi/requests@2.31.0"]
    lines = (data_dir / "demo" / f"sbom-{body['scan_id']}.txt").read_text(encoding="utf-8").splitlines()
    assert lines.count("flask 3.0.0 PyPI") == 2  # 목록 파일은 줄마다 기록하는 기존 규칙 유지


def test_pypi_name_is_normalized_in_purl_only(client, data_dir):
    body = upload(client, content=b"Flask_Login==0.6.3\nzope.interface==6.0\n").json()
    doc = read_cdx(data_dir, body)
    assert [c["purl"] for c in doc["components"]] == [
        "pkg:pypi/flask-login@0.6.3", "pkg:pypi/zope-interface@6.0"]
    assert [c["name"] for c in doc["components"]] == ["Flask_Login", "zope.interface"]  # 이름은 원문
    lines = (data_dir / "demo" / f"sbom-{body['scan_id']}.txt").read_text(encoding="utf-8").splitlines()
    assert "Flask_Login 0.6.3 PyPI" in lines  # 목록 파일의 이름도 원문


# ---- purl 규칙 (생태계별) ----

@pytest.mark.parametrize("eco,name,version,expected", [
    (ECO_PYPI, "Flask_Login", "0.6.3", "pkg:pypi/flask-login@0.6.3"),
    (ECO_PYPI, "a--b__c..d", "1", "pkg:pypi/a-b-c-d@1"),
    (ECO_PYPI, "flask", None, "pkg:pypi/flask"),
    (ECO_NPM, "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
    (ECO_NPM, "@babel/core", "7.23.0", "pkg:npm/%40babel/core@7.23.0"),  # 스코프는 %40
    (ECO_NPM, "@scope/name", None, "pkg:npm/%40scope/name"),
    (ECO_GO, "github.com/gorilla/mux", "v1.8.0", "pkg:golang/github.com/gorilla/mux@v1.8.0"),
    (ECO_GO, "golang.org/x/text", "v0.3.7", "pkg:golang/golang.org/x/text@v0.3.7"),
    (ECO_CRATES, "serde", "1.0.100", "pkg:cargo/serde@1.0.100"),
    (ECO_PYPI, "x", "1.0+local", "pkg:pypi/x@1.0%2Blocal"),  # 버전의 +는 퍼센트 인코딩
])
def test_purl_rules(eco, name, version, expected):
    assert cyclonedx.purl(eco, name, version) == expected


# ---- 문서 구조 ----

def test_top_level_metadata_is_deterministic_and_in_kst():
    t = datetime(2026, 11, 9, 11, 30, 5, tzinfo=KST)
    pk = [Package("flask", "3.0.0")]
    a = cyclonedx.build("demo", "20261109-113005", t, pk)
    b = cyclonedx.build("demo", "20261109-113005", t, pk)
    assert a == b  # 요청마다 결정적(같은 입력이면 같은 문서)
    assert a["serialNumber"].startswith("urn:uuid:")
    uuid.UUID(a["serialNumber"].removeprefix("urn:uuid:"))  # 올바른 uuid
    assert a["metadata"]["timestamp"] == "2026-11-09T11:30:05+09:00"
    assert a["metadata"]["component"] == {"type": "application", "name": "demo"}
    assert a["metadata"]["tools"]["components"][0]["name"] == "sbom-web"
    other_project = cyclonedx.build("other", "20261109-113005", t, pk)["serialNumber"]
    other_scan = cyclonedx.build("demo", "20261109-113006", t, pk)["serialNumber"]
    assert len({a["serialNumber"], other_project, other_scan}) == 3


def test_timestamp_is_kst_even_if_clock_gives_utc():
    t = datetime(2026, 11, 9, 2, 30, 5, tzinfo=timezone.utc)
    doc = cyclonedx.build("demo", "20261109-113005", t, [Package("a", "1")])
    assert doc["metadata"]["timestamp"] == "2026-11-09T11:30:05+09:00"


def test_bom_refs_are_unique_even_for_unpinned_duplicates():
    pk = parse_requirements("flask>=2.0\nflask<3\nflask\nclick\n").packages
    doc = cyclonedx.build("demo", "20261109-113005", datetime(2026, 11, 9, tzinfo=KST), pk)
    refs = [c["bom-ref"] for c in doc["components"]]
    assert len(refs) == len(set(refs)) == 4
    assert refs[0] == "pkg:pypi/flask" and refs[1] == "pkg:pypi/flask#2"
    assert_valid(doc)
    props = [c["properties"][0]["value"] for c in doc["components"] if c["name"] == "flask"]
    assert props == [">=2.0", "<3", "-"]


def test_no_vulnerabilities_in_the_cyclonedx_file(make_client, data_dir):
    body = upload(make_client(FakeSource(SET_D)), content=b"flask==3.0.0\n").json()
    assert body["vulnerabilities_total"] == 1  # 취약점이 있어도
    doc = read_cdx(data_dir, body)
    assert "vulnerabilities" not in doc
    assert "TEST-0001" not in cdx_path(data_dir, body["scan_id"]).read_text(encoding="utf-8")


def test_schema_validator_really_rejects_bad_documents():
    good = cyclonedx.build("demo", "20261109-113005", datetime(2026, 11, 9, tzinfo=KST), [Package("a", "1")])
    assert_valid(good)
    bad = json.loads(json.dumps(good))
    del bad["bomFormat"]
    with pytest.raises(AssertionError):
        assert_valid(bad)
    bad2 = json.loads(json.dumps(good))
    bad2["components"][0]["type"] = "not-a-type"
    with pytest.raises(AssertionError):
        assert_valid(bad2)


def test_empty_name_and_odd_characters_still_validate():
    pk = [Package("a b", "1.0"), Package("한글", "1"), Package("x", "1.0-rc.1+build.5")]
    assert_valid(cyclonedx.build("demo", "20261109-113005", datetime(2026, 11, 9, tzinfo=KST), pk))


# ---- 저장과 실패 처리 ----

def test_cyclonedx_write_failure_is_only_a_warning(client, data_dir, monkeypatch):
    import app.storage as storage
    real = os.replace

    def replace(src, dst):
        if str(dst).endswith(".cdx.json"):
            raise OSError("disk full")
        return real(src, dst)

    monkeypatch.setattr(storage.os, "replace", replace)
    r = upload(client)
    body = r.json()
    assert r.status_code == 201
    assert "CycloneDX 파일 저장 실패" in body["warnings"]
    assert body["links"]["cyclonedx"] is None
    folder = data_dir / "demo"
    assert (folder / f"sbom-{body['scan_id']}.txt").exists()  # 목록 파일은 정상
    assert (folder / f"vuln-report-{body['scan_id']}.txt").exists()  # 보고서도 정상
    assert not list(folder.glob("*.cdx.json")) and not list(folder.glob(".*"))  # 불완전한 파일 없음


def test_not_created_when_validation_fails_or_same_second_conflict(make_client, data_dir):
    c = make_client()
    assert upload(c, content=b"").status_code == 400
    assert upload(c, project="a b").status_code == 400
    assert not data_dir.exists() or not list(data_dir.rglob("*.cdx.json"))

    from datetime import datetime as dt
    fixed = dt(2026, 11, 9, 10, 0, 0, tzinfo=KST)
    c1 = make_client(clock=lambda: fixed)
    assert upload(c1).status_code == 201
    first = cdx_path(data_dir, "20261109-100000").read_bytes()
    assert upload(c1, content=b"django==4.2.0\n").status_code == 409
    assert cdx_path(data_dir, "20261109-100000").read_bytes() == first  # 충돌한 요청은 덮어쓰지 않는다


def test_not_created_when_the_list_file_cannot_be_saved(make_client, data_dir):
    data_dir.parent.mkdir(parents=True, exist_ok=True)
    data_dir.write_bytes(b"")  # 데이터 폴더 자리에 파일이 있어 저장 불가
    r = upload(make_client())
    assert r.status_code == 500
    assert data_dir.is_file()


def test_lookup_failure_keeps_the_cyclonedx_file(make_client, data_dir):
    # 구성요소 목록은 취약점 조회와 무관하므로, 조회가 실패해도 목록과 함께 이미 만들어져 있다
    r = upload(make_client(FakeSource(SET_D, fail=True)), content=FILE_A)
    assert r.status_code == 502
    assert cdx_path(data_dir, r.json()["scan_id"]).exists()


# ---- 이력과 내려받기 ----

def test_download_matches_stored_file_and_headers(client, data_dir):
    body = upload(client).json()
    assert body["links"]["cyclonedx"] == f"/api/projects/demo/scans/{body['scan_id']}/cyclonedx"
    r = client.get(body["links"]["cyclonedx"])
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert f'filename="sbom-{body["scan_id"]}.cdx.json"' in r.headers["content-disposition"]
    assert "attachment" in r.headers["content-disposition"]
    assert r.text == cdx_path(data_dir, body["scan_id"]).read_text(encoding="utf-8")
    assert r.json()["bomFormat"] == "CycloneDX"


def test_download_404_for_missing_file_and_bad_scan_id_400_for_bad_name(client, data_dir):
    old = data_dir / "demo"
    old.mkdir(parents=True)
    (old / "sbom-20261101-090000.txt").write_text("# SBOM 목록\nflask 3.0.0 PyPI\n", encoding="utf-8")
    assert client.get("/api/projects/demo/scans/20261101-090000/cyclonedx").status_code == 404  # 파일 없음
    assert client.get("/api/projects/demo/scans/abc/cyclonedx").status_code == 404
    assert client.get("/api/projects/demo/scans/..%2F..%2Fx/cyclonedx").status_code == 404
    assert client.get("/api/projects/a b/scans/20261101-090000/cyclonedx").status_code == 400
    assert client.get("/api/projects/..%2Fx/scans/20261101-090000/cyclonedx").status_code == 400


def test_history_links_cyclonedx_null_for_old_scans_and_present_for_new(client, data_dir):
    old = data_dir / "demo"
    old.mkdir(parents=True)
    (old / "sbom-20200101-000000.txt").write_text("# SBOM 목록\nflask 3.0.0 PyPI\n", encoding="utf-8")
    new = upload(client).json()
    scans = client.get("/api/projects/demo/scans").json()["scans"]
    by_id = {s["scan_id"]: s for s in scans}
    assert by_id["20200101-000000"]["links"]["cyclonedx"] is None  # 파일이 없는 과거 스캔
    assert by_id[new["scan_id"]]["links"]["cyclonedx"] == f"/api/projects/demo/scans/{new['scan_id']}/cyclonedx"


def test_cdx_json_does_not_count_as_a_scan_or_confuse_previous_lookup(data_dir):
    folder = data_dir / "demo"
    folder.mkdir(parents=True)
    # .cdx.json만 있는 경우는 스캔이 아니다
    (folder / "sbom-20261109-100000.cdx.json").write_text("{}", encoding="utf-8")
    assert list_scans(data_dir, "demo") == []
    assert previous_scan_id(data_dir, "demo", "20261109-110000") is None
    # 목록 파일이 있는 스캔과 .cdx.json이 섞여도 스캔은 목록 파일 기준으로 한 번씩만 센다
    (folder / "sbom-20261109-100000.txt").write_text("# SBOM 목록\nflask 3.0.0 PyPI\n", encoding="utf-8")
    (folder / "sbom-20261109-090000.cdx.json").write_text("{}", encoding="utf-8")
    scans = list_scans(data_dir, "demo")
    assert [(s.scan_id, s.has_cyclonedx) for s in scans] == [("20261109-100000", True)]
    assert previous_scan_id(data_dir, "demo", "20261109-110000") == "20261109-100000"


def test_comparison_and_previous_list_are_unchanged_by_cyclonedx(make_client, data_dir):
    from .test_t7 import scan
    scan(make_client, (2026, 11, 9, 10, 0, 0), content=FILE_A)
    body = scan(make_client, (2026, 11, 9, 11, 0, 0), content=b"flask==3.0.1\nclick==8.1.7\n").json()
    assert body["comparison"]["lines"][1:] == [
        "추가 1: click 8.1.7 PyPI", "삭제 1: requests 2.31.0 PyPI",
        "변경 1: flask 3.0.0 -> 3.0.1 PyPI", "변경 없음 0"]
    txt = (data_dir / "demo" / f"sbom-{body['scan_id']}.txt").read_text(encoding="utf-8")
    assert "{" not in txt  # JSON이 목록 파일에 섞이지 않는다


def test_cyclonedx_file_is_valid_json_with_utf8_and_trailing_newline(client, data_dir):
    body = upload(client, content="flask==3.0.0\n".encode()).json()
    raw = cdx_path(data_dir, body["scan_id"]).read_bytes()
    assert raw.endswith(b"\n")
    json.loads(raw.decode("utf-8"))
