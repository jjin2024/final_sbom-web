"""T13: 작은 정확도 개선 두 가지.
1) extras가 붙은 줄(`flask[async]==3.0.0`)을 이름과 버전으로 읽는다 (후보 C12)
2) 이전 실행 대비에서 PyPI 이름을 PEP 503 규칙으로 정규화해 비교한다 (후보 C11)"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.compare import compare
from app.parser import Package, parse_requirements
from app.storage import render_sbom

from .conftest import upload
from .fakes import FakeSource
from .test_t7 import scan

KST = timezone(timedelta(hours=9))


def at(h, m=0, s=0):
    return lambda: datetime(2026, 11, 9, h, m, s, tzinfo=KST)


def entries(data_dir, body, project="demo"):
    out = []
    for line in (data_dir / project / f"sbom-{body['scan_id']}.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("##"):
            break
        if not line.startswith("#"):
            out.append(line)
    return out


# ================= 1. extras =================

@pytest.mark.parametrize("line,name,version,pinned", [
    ("flask[async]==3.0.0", "flask", "3.0.0", True),
    ("uvicorn[standard]==0.30.0", "uvicorn", "0.30.0", True),
    ("flask[async,dotenv]==3.0.0", "flask", "3.0.0", True),            # extras가 여럿
    ("requests[socks]==2.31.0", "requests", "2.31.0", True),
    ("Django[argon2]==4.2.0", "Django", "4.2.0", True),                # 이름은 원문 유지
    ("flask[async]==3.0.0  # 주석", "flask", "3.0.0", True),
    ("flask[async]==3.0.0; python_version>'3.8'", "flask", "3.0.0", True),  # 환경 마커는 기존처럼 버림
    ("flask[async] == 3.0.0", "flask", "3.0.0", True),                 # 닫는 대괄호 뒤의 공백은 기존 규칙(연산자 앞 공백)과 같다
    ("flask[async]>=2.0", "flask", ">=2.0", False),                    # 범위 표기는 기존 규칙대로 확정 버전 아님
    ("flask[async]>=2.0,<3", "flask", ">=2.0,<3", False),
    ("flask[async]~=2.1", "flask", "~=2.1", False),
    ("flask[async]==2.*", "flask", "==2.*", False),
    ("flask[async]", "flask", "-", False),                             # 버전 없음
])
def test_extras_are_dropped_and_only_name_and_version_are_read(line, name, version, pinned):
    r = parse_requirements(line + "\n")
    assert [(p.name, p.version, p.pinned, p.ecosystem) for p in r.packages] == [(name, version, pinned, "PyPI")]
    assert r.skipped_lines == 0


@pytest.mark.parametrize("line", [
    "flask[async==3.0",            # 대괄호가 닫히지 않음
    "flask[async",
    "flask[async]]==3.0",
    "name [extra] == 1.0",         # 이름과 대괄호 사이에 공백
    "flask [async]==3.0.0",
    "flask[ async ]==3.0.0",       # 대괄호 안의 공백
    "flask[async, dotenv]==3.0.0",
    "flask[]==3.0.0",              # 빈 대괄호
    "flask[,]==3.0.0",
    "flask[-bad]==3.0.0",
    "[async]==3.0.0",              # 이름이 없음
    "flask[async]foo==1.0",
])
def test_malformed_extras_lines_are_skipped_and_counted(line):
    r = parse_requirements(line + "\nrequests==2.31.0\n")
    assert [p.name for p in r.packages] == ["requests"]
    assert r.skipped_lines == 1


def test_existing_requirement_rules_are_unchanged():
    text = "flask==3.0.0\nclick\nrequests>=2.0\n-r other.txt\ngit+https://github.com/x/y.git\n# 주석\n\n"
    r = parse_requirements(text)
    assert [(p.name, p.version, p.pinned) for p in r.packages] == [
        ("flask", "3.0.0", True), ("click", "-", False), ("requests", ">=2.0", False)]
    assert r.skipped_lines == 2


# ---- 업로드 흐름: 목록 파일, 조회, CycloneDX ----

def test_upload_with_extras_lists_plain_names_looks_them_up_and_omits_extras_everywhere(make_client, data_dir):
    src = FakeSource()
    body = upload(make_client(src), content=b"flask[async]==3.0.0\nuvicorn[standard]==0.30.0\n").json()
    assert body["collected"] == 2 and body["skipped_lines"] == 0 and body["not_looked_up"] == 0
    assert entries(data_dir, body) == ["flask 3.0.0 PyPI", "uvicorn 0.30.0 PyPI"]  # extras는 목록에 없다
    assert sorted(src.calls) == [("flask", "3.0.0", "PyPI"), ("uvicorn", "0.30.0", "PyPI")]  # 이름과 버전만 조회
    cdx = json.loads((data_dir / "demo" / f"sbom-{body['scan_id']}.cdx.json").read_text(encoding="utf-8"))
    assert [(c["name"], c["version"], c["purl"]) for c in cdx["components"]] == [
        ("flask", "3.0.0", "pkg:pypi/flask@3.0.0"), ("uvicorn", "0.30.0", "pkg:pypi/uvicorn@0.30.0")]
    # 어떤 파일에도 extras 이름이 없고, 목록 파일과 구성요소의 이름·purl에는 대괄호도 없다
    everything = "".join(p.read_text(encoding="utf-8") for p in (data_dir / "demo").iterdir())
    assert "async" not in everything and "standard" not in everything
    assert not any("[" in line for line in entries(data_dir, body))
    assert not any("[" in c["name"] + c["purl"] for c in cdx["components"])


def test_upload_with_malformed_extras_counts_skipped_lines_and_continues(make_client, data_dir):
    src = FakeSource()
    body = upload(make_client(src), content=b"flask[async==3.0\nname [extra] == 1.0\nrequests==2.31.0\n").json()
    assert body["collected"] == 1 and body["skipped_lines"] == 2
    assert entries(data_dir, body) == ["requests 2.31.0 PyPI"]
    assert src.calls == [("requests", "2.31.0", "PyPI")]  # 요청은 끝까지 진행


def test_extras_with_a_range_is_not_looked_up_and_keeps_the_spec_in_cyclonedx(make_client, data_dir):
    src = FakeSource()
    body = upload(make_client(src), content=b"flask[async]>=2.0\nrequests==2.31.0\n").json()
    assert body["not_looked_up"] == 1
    assert entries(data_dir, body) == ["flask >=2.0 PyPI (확정 버전 아님)", "requests 2.31.0 PyPI"]
    assert src.calls == [("requests", "2.31.0", "PyPI")]
    cdx = json.loads((data_dir / "demo" / f"sbom-{body['scan_id']}.cdx.json").read_text(encoding="utf-8"))
    flask = next(c for c in cdx["components"] if c["name"] == "flask")
    assert "version" not in flask and flask["purl"] == "pkg:pypi/flask"
    assert flask["properties"] == [{"name": "sbom-web:version-spec", "value": ">=2.0"}]


def test_same_package_with_and_without_extras_is_listed_per_line_but_looked_up_once(make_client, data_dir):
    src = FakeSource()
    body = upload(make_client(src), content=b"flask==3.0.0\nflask[async]==3.0.0\n").json()
    assert entries(data_dir, body) == ["flask 3.0.0 PyPI", "flask 3.0.0 PyPI"]  # 목록은 줄마다
    assert src.calls == [("flask", "3.0.0", "PyPI")]  # 조회는 한 번
    cdx = json.loads((data_dir / "demo" / f"sbom-{body['scan_id']}.cdx.json").read_text(encoding="utf-8"))
    assert len(cdx["components"]) == 1


# ================= 2. 이전 실행 대비의 PyPI 이름 정규화 =================

def _compare(old_text: bytes, new_text: bytes, make_client, project="demo"):
    scan(make_client, (2026, 11, 9, 10, 0, 0), content=old_text, project=project)
    return scan(make_client, (2026, 11, 9, 11, 0, 0), content=new_text, project=project).json()["comparison"]


def test_different_spelling_with_the_same_version_is_unchanged(make_client):
    c = _compare(b"Flask_Login==0.6.3\n", b"flask-login==0.6.3\n", make_client)
    assert (c["added"], c["removed"], c["changed"], c["unchanged"]) == ([], [], [], 1)
    assert c["lines"][1:] == ["추가 0", "삭제 0", "변경 0", "변경 없음 1"]


def test_different_spelling_with_a_different_version_is_a_change_shown_with_the_new_name(make_client, data_dir):
    scan(make_client, (2026, 11, 9, 10, 0, 0), content=b"Flask_Login==0.6.2\n")
    body = scan(make_client, (2026, 11, 9, 11, 0, 0), content=b"flask-login==0.6.3\n").json()
    c = body["comparison"]
    assert c["changed"] == [{"name": "flask-login", "from": "0.6.2", "to": "0.6.3", "ecosystem": "PyPI"}]
    assert c["added"] == [] and c["removed"] == [] and c["unchanged"] == 0
    assert c["lines"][3] == "변경 1: flask-login 0.6.2 -> 0.6.3 PyPI"  # 새 요청의 원문 이름
    text = (data_dir / "demo" / f"sbom-{body['scan_id']}.txt").read_text(encoding="utf-8")
    assert "변경 1: flask-login 0.6.2 -> 0.6.3 PyPI" in text  # 파일에도 같은 내용
    assert "Flask_Login" not in text


@pytest.mark.parametrize("old,new", [
    ("Flask", "flask"),
    ("FLASK", "flask"),
    ("flask_login", "flask-login"),
    ("flask.login", "flask-login"),
    ("Flask__Login", "flask-login"),     # 구분자의 연속은 - 하나로
    ("flask-.-login", "flask-login"),
    ("zope.interface", "Zope_Interface"),
    ("ruamel.yaml", "ruamel-yaml"),
])
def test_pep_503_equivalent_names_compare_as_unchanged(make_client, old, new):
    c = _compare(f"{old}==1.0\n".encode(), f"{new}==1.0\n".encode(), make_client)
    assert (len(c["added"]), len(c["removed"]), len(c["changed"]), c["unchanged"]) == (0, 0, 0, 1)


@pytest.mark.parametrize("old,new", [("flask", "flask-login"), ("flaskx", "flask"), ("a-b", "ab")])
def test_genuinely_different_names_are_still_added_and_removed(make_client, old, new):
    c = _compare(f"{old}==1.0\n".encode(), f"{new}==1.0\n".encode(), make_client)
    assert [i["name"] for i in c["added"]] == [new] and [i["name"] for i in c["removed"]] == [old]
    assert c["unchanged"] == 0 and c["changed"] == []


def test_a_removed_item_keeps_the_name_from_the_previous_file(make_client):
    c = _compare(b"Flask_Login==0.6.3\nrequests==2.31.0\n", b"requests==2.31.0\n", make_client)
    assert c["removed"] == [{"name": "Flask_Login", "version": "0.6.3", "ecosystem": "PyPI"}]  # 이전 파일의 표기
    assert c["unchanged"] == 1


def test_added_item_uses_the_name_exactly_as_written_in_the_new_request(make_client):
    c = _compare(b"requests==2.31.0\n", b"requests==2.31.0\nFlask_Login==0.6.3\n", make_client)
    assert c["added"] == [{"name": "Flask_Login", "version": "0.6.3", "ecosystem": "PyPI"}]


def test_two_spellings_in_one_file_count_as_one_package(make_client):
    c = _compare(b"Flask_Login==0.6.3\n", b"flask-login==0.6.3\nFlask.Login==0.6.3\n", make_client)
    assert (c["added"], c["removed"], c["changed"], c["unchanged"]) == ([], [], [], 1)
    c2 = _compare(b"flask-login==0.6.3\n", b"flask-login==0.6.3\nFlask.Login==0.6.4\n", make_client, project="other")
    assert len(c2["changed"]) == 1 and c2["changed"][0]["to"] == "0.6.3, 0.6.4"  # 같은 패키지의 두 버전


def test_range_notation_change_still_counts_even_if_the_spelling_differs(make_client):
    c = _compare(b"Flask_Login>=0.6\n", b"flask-login>=0.7\n", make_client)
    assert c["changed"] == [{"name": "flask-login", "from": ">=0.6", "to": ">=0.7", "ecosystem": "PyPI"}]


# ---- 다른 생태계는 정규화하지 않는다 ----

def _compare_lists(old_lines: list[str], new_packages: list[Package], tmp_path):
    old = tmp_path / "sbom-20261109-100000.txt"
    old.write_text(render_sbom("demo", datetime(2026, 11, 9, 10, tzinfo=KST), []) + "\n".join(old_lines) + "\n",
                   encoding="utf-8")
    return compare("20261109-100000", old, new_packages)


def test_npm_go_and_cargo_names_are_not_normalized(tmp_path):
    new = [Package("lodash", "4.17.21", "npm"), Package("github.com/foo/bar", "v1.0.0", "Go"),
           Package("serde-json", "1.0.0", "crates.io"), Package("my_pkg", "1.0.0", "npm")]
    c = _compare_lists(["Lodash 4.17.21 npm", "github.com/Foo/bar v1.0.0 Go",
                        "serde_json 1.0.0 crates.io", "my-pkg 1.0.0 npm"], new, tmp_path)
    assert c.unchanged == 0 and c.changed == []
    assert sorted(i[0] for i in c.added) == sorted(["lodash", "github.com/foo/bar", "serde-json", "my_pkg"])
    assert sorted(i[0] for i in c.removed) == sorted(["Lodash", "github.com/Foo/bar", "serde_json", "my-pkg"])


def test_a_pypi_name_and_an_npm_name_that_normalize_alike_stay_separate(tmp_path):
    c = _compare_lists(["Flask_Login 1.0 PyPI"], [Package("flask-login", "1.0", "npm")], tmp_path)
    assert [i[2] for i in c.added] == ["npm"] and [i[2] for i in c.removed] == ["PyPI"]


def test_list_file_and_lookup_keep_the_original_spelling(make_client, data_dir):
    src = FakeSource()
    scan(make_client, (2026, 11, 9, 10, 0, 0), content=b"Flask_Login==0.6.3\n", source=src)
    body = scan(make_client, (2026, 11, 9, 11, 0, 0), content=b"flask-login==0.6.3\n", source=src).json()
    assert src.calls == [("Flask_Login", "0.6.3", "PyPI"), ("flask-login", "0.6.3", "PyPI")]  # OSV에는 원문 그대로
    assert entries(data_dir, body) == ["flask-login 0.6.3 PyPI"]  # 목록 파일의 이름 표기도 원문
    old = (data_dir / "demo" / "sbom-20261109-100000.txt").read_text(encoding="utf-8")
    assert "Flask_Login 0.6.3 PyPI" in old  # 이전 파일은 바뀌지 않는다
    assert body["comparison"]["unchanged"] == 1


def test_extras_and_normalization_work_together_across_requests(make_client):
    c = _compare(b"Flask_Login[async]==0.6.3\n", b"flask-login==0.6.3\n", make_client)
    assert (len(c["added"]), len(c["removed"]), len(c["changed"]), c["unchanged"]) == (0, 0, 0, 1)
