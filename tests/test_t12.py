"""T12: 입력 파일 종류 확대, Node.js(package-lock.json, package.json), Go(go.mod), Rust(Cargo.lock) (R1-5)."""
import json
import os

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.parser import (
    ECO_CRATES, ECO_GO, ECO_NPM, FormatError, parse_cargo_lock, parse_go_mod,
    parse_package_json, parse_package_lock, parse_requirements, parse_upload,
)

from .conftest import (
    FILE_A, FILE_J, FILE_K, FILE_L, FILE_M, FILE_N, FILE_O, FILE_P, upload,
)
from .fakes import SET_GO, SET_NPM, SET_RUST, FakeSource


def send(client, filename, content, project="demo"):
    return client.post(f"/api/projects/{project}/scans", files={"file": (filename, content)})


def list_lines(data_dir, body, project="demo"):
    text = (data_dir / project / f"sbom-{body['scan_id']}.txt").read_text(encoding="utf-8")
    out = []
    for line in text.splitlines():
        if line.startswith("##"):
            break
        if not line.startswith("#"):
            out.append(line)
    return out


def names(result):
    return [(p.name, p.version, p.ecosystem, p.pinned) for p in result.packages]


# ================= 해석기 단위 시험 =================

def test_package_lock_basic_rules():
    r = parse_package_lock(FILE_J.decode())
    assert names(r) == [
        ("lodash", "4.17.15", "npm", True),
        ("express", "4.18.2", "npm", True),
        ("@babel/core", "7.23.0", "npm", True),
    ]
    assert r.skipped_lines == 1  # link 항목. 루트("")는 프로젝트 자신이라 세지 않는다
    assert r.not_looked_up == 0


def test_package_lock_name_comes_from_the_last_node_modules_segment():
    lock = {"lockfileVersion": 3, "packages": {
        "": {"name": "root"},
        "node_modules/express": {"version": "4.18.2"},
        "node_modules/express/node_modules/qs": {"version": "6.11.0"},
        "node_modules/a/node_modules/@scope/pkg": {"version": "1.0.0"},
        "node_modules/@types/node": {"version": "20.1.0"},
    }}
    got = [(p.name, p.version) for p in parse_package_lock(json.dumps(lock)).packages]
    assert got == [("express", "4.18.2"), ("qs", "6.11.0"), ("@scope/pkg", "1.0.0"), ("@types/node", "20.1.0")]


def test_package_lock_skips_entries_without_usable_data_and_counts_them():
    lock = {"lockfileVersion": 2, "packages": {
        "": {"name": "root", "version": "1.0.0"},
        "node_modules/ok": {"version": "1.0.0"},
        "node_modules/linked": {"link": True, "resolved": "../x"},
        "node_modules/noversion": {"resolved": "x"},
        "node_modules/emptyversion": {"version": ""},
        "node_modules/badtype": {"version": 3},
        "node_modules/notdict": "oops",
        "packages/app": {"version": "1.0.0"},  # node_modules 아래가 아닌 작업 공간 폴더
    }}
    r = parse_package_lock(json.dumps(lock))
    assert [p.name for p in r.packages] == ["ok"]
    assert r.skipped_lines == 6


def test_package_lock_version_1_and_other_shapes_are_rejected():
    with pytest.raises(FormatError, match="지원하지 않는 lockfile 버전"):
        parse_package_lock(FILE_O.decode())
    with pytest.raises(FormatError, match="지원하지 않는 lockfile 버전"):
        parse_package_lock('{"lockfileVersion": 3}')  # packages 자체가 없음
    with pytest.raises(FormatError, match="지원하지 않는 lockfile 버전"):
        parse_package_lock('{"packages": []}')


@pytest.mark.parametrize("text", [
    FILE_N.decode(), "", "not json", "[1, 2]", "null",
    pytest.param("[" * 100000, id="deeply-nested"),  # RecursionError도 형식 오류로 처리(긴 값은 시험 이름에 쓰지 않는다)
])
def test_json_files_with_bad_syntax_or_shape_are_format_errors(text):
    with pytest.raises(FormatError, match="형식을 해석할 수 없음"):
        parse_package_lock(text)
    with pytest.raises(FormatError, match="형식을 해석할 수 없음"):
        parse_package_json(text)


def test_package_json_classifies_exact_versions_and_ranges():
    r = parse_package_json(FILE_K.decode())
    assert names(r) == [
        ("lodash", "4.17.15", "npm", True),
        ("express", "^4.18.0", "npm", False),
        ("left-pad", "latest", "npm", False),
        ("mocha", "10.2.0", "npm", True),  # devDependencies도 읽는다
    ]
    assert r.not_looked_up == 2 and r.skipped_lines == 0


@pytest.mark.parametrize("spec,pinned,shown", [
    ("1.2.3", True, "1.2.3"),
    ("0.0.1", True, "0.0.1"),
    ("1.2.3-beta.1", True, "1.2.3-beta.1"),       # 프리릴리스 접미사 허용
    ("1.2.3+build.5", True, "1.2.3+build.5"),     # 빌드 접미사 허용
    ("1.2.3-rc.1+exp.sha.5114f85", True, "1.2.3-rc.1+exp.sha.5114f85"),
    ("  1.2.3  ", True, "1.2.3"),
    ("^1.2.3", False, "^1.2.3"),
    ("~1.2.3", False, "~1.2.3"),
    (">=1.0.0", False, ">=1.0.0"),
    (">=1.0.0 <2.0.0", False, ">=1.0.0<2.0.0"),   # 공백은 제거(목록 파일의 줄이 세 칸으로 유지되게)
    ("1.x", False, "1.x"),
    ("1.2", False, "1.2"),
    ("*", False, "*"),
    ("latest", False, "latest"),
    ("", False, "-"),
    ("git+https://github.com/x/y.git#v1", False, "git+https://github.com/x/y.git#v1"),
    ("https://example.com/x.tgz", False, "https://example.com/x.tgz"),
    ("workspace:*", False, "workspace:*"),
    ("npm:other@1.0.0", False, "npm:other@1.0.0"),
    ("file:../local", False, "file:../local"),
    ("v1.2.3", False, "v1.2.3"),                    # x.y.z가 아닌 표기는 정확한 버전으로 보지 않는다
])
def test_package_json_version_notations(spec, pinned, shown):
    r = parse_package_json(json.dumps({"dependencies": {"pkg": spec}}))
    assert names(r) == [("pkg", shown, "npm", pinned)]


def test_package_json_same_name_in_both_sections_is_recorded_twice():
    r = parse_package_json('{"dependencies": {"a": "1.0.0"}, "devDependencies": {"a": "2.0.0"}}')
    assert names(r) == [("a", "1.0.0", "npm", True), ("a", "2.0.0", "npm", True)]


def test_package_json_without_dependencies_or_with_wrong_types():
    assert parse_package_json('{"name": "x"}').packages == []
    r = parse_package_json('{"dependencies": {"a": 1, "b": null, "c": "1.0.0"}}')
    assert [p.name for p in r.packages] == ["c"] and r.skipped_lines == 2
    with pytest.raises(FormatError, match="dependencies"):
        parse_package_json('{"dependencies": ["a"]}')


def test_go_mod_basic_rules():
    r = parse_go_mod(FILE_L.decode())
    assert names(r) == [
        ("github.com/gin-gonic/gin", "v1.9.0", "Go", True),
        ("golang.org/x/text", "v0.3.7", "Go", True),   # // indirect 주석은 버리고 항목은 남긴다
        ("github.com/gorilla/mux", "v1.8.0", "Go", True),
    ]
    assert r.skipped_lines == 0  # module, go, replace 줄은 정상 내용이라 건너뛴 줄이 아님


def test_go_mod_directives_blocks_comments_and_odd_formatting():
    text = (
        "// 주석만 있는 줄\n"
        "module example.com/x\n"
        "go 1.22\n"
        "toolchain go1.22.3\n"
        "require\tgithub.com/a/b\tv1.0.0\n"            # 탭 구분
        "require (\n"
        "\n"
        "\t// 블록 안의 주석\n"
        "\tgithub.com/c/d v0.0.0-20210101000000-abcdef123456\n"   # 의사 버전
        "\tgithub.com/e/f v2.1.0+incompatible\n"
        "\tbad-line-without-version\n"                  # 해석할 수 없는 줄
        ")\n"
        "replace (\n"
        "\tgithub.com/a/b => ../b\n"
        "\tgithub.com/c/d => github.com/fork/d v1.0.0\n"
        ")\n"
        "exclude github.com/x/y v1.0.0\n"
        "retract v1.0.1\n"
        "retract (\n"
        "\tv1.0.2\n"
        ")\n"
        "unknown-directive foo\n"                     # 알 수 없는 지시어
        "require github.com/g/h\n"                    # 버전이 없는 한 줄 require
    )
    r = parse_go_mod(text)
    assert [(p.name, p.version) for p in r.packages] == [
        ("github.com/a/b", "v1.0.0"),
        ("github.com/c/d", "v0.0.0-20210101000000-abcdef123456"),
        ("github.com/e/f", "v2.1.0+incompatible"),
    ]
    # 읽을 수 없는 줄만 센다: 블록 안의 버전 없는 항목 1 + 알 수 없는 지시어 1 + 버전 없는 한 줄 require 1.
    # module, go, toolchain, replace, exclude, retract(블록 포함), 주석, 빈 줄은 세지 않는다
    assert r.skipped_lines == 3


def test_go_mod_empty_or_without_requirements_yields_no_packages():
    assert parse_go_mod("").packages == []
    r = parse_go_mod("module x\n\ngo 1.21\n")
    assert r.packages == [] and r.skipped_lines == 0


def test_cargo_lock_basic_rules():
    r = parse_cargo_lock(FILE_M.decode())
    assert names(r) == [("serde", "1.0.100", "crates.io", True), ("time", "0.1.43", "crates.io", True)]
    assert r.skipped_lines == 1  # source가 없는 자기 자신


def test_cargo_lock_skips_non_registry_sources_and_broken_entries():
    text = '''
[[package]]
name = "a"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "b"
version = "2.0.0"
source = "sparse+https://index.crates.io/"

[[package]]
name = "gitdep"
version = "0.1.0"
source = "git+https://github.com/x/y#abc"

[[package]]
name = "private"
version = "0.1.0"
source = "registry+https://my.registry.example/index"

[[package]]
name = "local"
version = "0.1.0"

[[package]]
name = "noversion"
source = "registry+https://github.com/rust-lang/crates.io-index"
'''
    r = parse_cargo_lock(text)
    assert [(p.name, p.version) for p in r.packages] == [("a", "1.0.0"), ("b", "2.0.0")]
    assert r.skipped_lines == 4


def test_cargo_lock_errors_and_empty():
    with pytest.raises(FormatError, match="형식을 해석할 수 없음"):
        parse_cargo_lock(FILE_P.decode())
    assert parse_cargo_lock("version = 3\n").packages == []
    with pytest.raises(FormatError):
        parse_cargo_lock('package = "oops"\n')


@pytest.mark.parametrize("filename,text,eco", [
    ("package-lock.json", FILE_J.decode(), ECO_NPM),
    ("package.json", FILE_K.decode(), ECO_NPM),
    ("go.mod", FILE_L.decode(), ECO_GO),
    ("Cargo.lock", FILE_M.decode(), ECO_CRATES),
    ("sub/dir/package.json", FILE_K.decode(), ECO_NPM),         # 경로 부분은 무시
    ("C:\\proj\\go.mod", FILE_L.decode(), ECO_GO),
])
def test_parse_upload_picks_the_parser_by_file_name(filename, text, eco):
    assert {p.ecosystem for p in parse_upload(filename, text).packages} == {eco}


@pytest.mark.parametrize("filename", ["requirements.txt", "my-deps.txt", "", None, "Package.json",
                                      "package-lock.json.bak", "cargo.lock", "go.mod.txt", "xgo.mod"])
def test_other_names_use_the_requirements_parser(filename):
    r = parse_upload(filename, "flask==3.0.0\n")
    assert names(r) == [("flask", "3.0.0", "PyPI", True)]
    assert names(r) == names(parse_requirements("flask==3.0.0\n"))


# ================= 업로드 흐름 (가짜 OSV) =================

def test_upload_package_lock(make_client, data_dir):
    src = FakeSource(SET_NPM)
    r = send(make_client(src), "package-lock.json", FILE_J)
    body = r.json()
    assert r.status_code == 201
    assert body["collected"] == 3 and body["skipped_lines"] == 1 and body["not_looked_up"] == 0
    assert list_lines(data_dir, body) == [
        "lodash 4.17.15 npm", "express 4.18.2 npm", "@babel/core 7.23.0 npm"]  # 루트와 link는 빠진다
    assert sorted(src.calls) == sorted([
        ("lodash", "4.17.15", "npm"), ("express", "4.18.2", "npm"), ("@babel/core", "7.23.0", "npm")])
    assert [(x["package"], x["vuln_id"], x["severity"]) for x in body["table"]] == [
        ("lodash", "TEST-N001", "높음"), ("@babel/core", "TEST-N002", "보통")]


def test_upload_package_json(make_client, data_dir):
    src = FakeSource(SET_NPM)
    r = send(make_client(src), "package.json", FILE_K)
    body = r.json()
    assert r.status_code == 201 and body["collected"] == 4 and body["not_looked_up"] == 2
    assert list_lines(data_dir, body) == [
        "lodash 4.17.15 npm", "express ^4.18.0 npm (확정 버전 아님)",
        "left-pad latest npm (확정 버전 아님)", "mocha 10.2.0 npm"]
    assert sorted(src.calls) == [("lodash", "4.17.15", "npm"), ("mocha", "10.2.0", "npm")]  # 범위와 latest는 조회 제외


def test_upload_go_mod_sends_the_version_exactly_as_written(make_client, data_dir):
    src = FakeSource(SET_GO)
    r = send(make_client(src), "go.mod", FILE_L)
    body = r.json()
    assert r.status_code == 201 and body["collected"] == 3 and body["skipped_lines"] == 0
    assert list_lines(data_dir, body) == [
        "github.com/gin-gonic/gin v1.9.0 Go", "golang.org/x/text v0.3.7 Go", "github.com/gorilla/mux v1.8.0 Go"]
    assert ("github.com/gin-gonic/gin", "v1.9.0", "Go") in src.calls  # v 접두사 그대로
    assert [x["vuln_id"] for x in body["table"]] == ["TEST-G001", "TEST-G002"]


def test_upload_cargo_lock(make_client, data_dir):
    src = FakeSource(SET_RUST)
    r = send(make_client(src), "Cargo.lock", FILE_M)
    body = r.json()
    assert r.status_code == 201 and body["collected"] == 2 and body["skipped_lines"] == 1
    assert list_lines(data_dir, body) == ["serde 1.0.100 crates.io", "time 0.1.43 crates.io"]
    assert sorted(src.calls) == [("serde", "1.0.100", "crates.io"), ("time", "0.1.43", "crates.io")]
    assert [x["vuln_id"] for x in body["table"]] == ["TEST-R002", "TEST-R001"]  # 높음, 낮음


@pytest.mark.parametrize("filename,content,message", [
    ("package-lock.json", FILE_N, "형식을 해석할 수 없음"),
    ("package.json", FILE_N, "형식을 해석할 수 없음"),
    ("package-lock.json", FILE_O, "지원하지 않는 lockfile 버전"),
    ("Cargo.lock", FILE_P, "형식을 해석할 수 없음"),
    ("package.json", b"flask==3.0.0\nrequests==2.31.0\n", "형식을 해석할 수 없음"),  # 이름과 내용이 안 맞음
])
def test_supported_name_with_wrong_content_is_400_and_nothing_happens(make_client, data_dir, filename, content, message):
    src = FakeSource(SET_NPM)
    r = send(make_client(src), filename, content)
    assert r.status_code == 400 and message in r.json()["error"]
    assert not data_dir.exists() or not any(data_dir.iterdir())  # 저장 없음
    assert src.calls == []                                         # 외부 호출 없음


@pytest.mark.parametrize("filename,content", [
    ("package-lock.json", b'{"lockfileVersion": 3, "packages": {"": {"name": "x"}}}'),
    ("package.json", b'{"name": "x"}'),
    ("go.mod", b"module x\n\ngo 1.21\n"),
    ("Cargo.lock", b"version = 3\n"),
])
def test_zero_packages_is_400_for_every_kind(make_client, data_dir, filename, content):
    src = FakeSource()
    r = send(make_client(src), filename, content)
    assert r.status_code == 400 and "패키지를 찾을 수 없음" in r.json()["error"]
    assert not data_dir.exists() and src.calls == []


def test_unknown_file_name_keeps_using_the_requirements_format(client, data_dir):
    r = send(client, "my-deps.txt", FILE_A)  # 사례 2와 같은 동작
    assert r.status_code == 201 and r.json()["collected"] == 2
    assert list_lines(data_dir, r.json()) == ["flask 3.0.0 PyPI", "requests 2.31.0 PyPI"]


def test_json_content_under_an_unknown_name_is_not_parsed_as_json(client):
    r = send(client, "deps.json", FILE_K)  # 이름이 지원하는 이름이 아니므로 requirements.txt 형식으로 본다
    assert r.status_code == 400 and "패키지를 찾을 수 없음" in r.json()["error"]


def test_comparison_across_ecosystems_shows_each_others_items_as_removed_and_added(make_client):
    from .test_t7 import scan
    scan(make_client, (2026, 11, 9, 10, 0, 0), content=FILE_A)  # PyPI 2건
    r = make_client(clock=lambda: __import__("datetime").datetime(
        2026, 11, 9, 11, 0, 0, tzinfo=__import__("datetime").timezone(__import__("datetime").timedelta(hours=9))))
    body = send(r, "package-lock.json", FILE_J).json()
    c = body["comparison"]
    assert c["status"] == "비교함"
    assert sorted(i["name"] for i in c["added"]) == ["@babel/core", "express", "lodash"]
    assert sorted(i["name"] for i in c["removed"]) == ["flask", "requests"]
    assert c["changed"] == [] and c["unchanged"] == 0  # 비교 키에 생태계가 들어 있어 서로 다른 항목이다


def test_same_name_in_different_ecosystems_is_not_confused_in_comparison(make_client):
    from .test_t7 import scan
    scan(make_client, (2026, 11, 9, 10, 0, 0), content=b"requests==2.31.0\n")
    import datetime as d
    r = make_client(clock=lambda: d.datetime(2026, 11, 9, 11, 0, 0, tzinfo=d.timezone(d.timedelta(hours=9))))
    body = send(r, "package.json", b'{"dependencies": {"requests": "2.31.0"}}').json()
    c = body["comparison"]
    assert [i["ecosystem"] for i in c["added"]] == ["npm"] and [i["ecosystem"] for i in c["removed"]] == ["PyPI"]


def test_cyclonedx_purls_for_every_ecosystem(make_client, data_dir):
    cases = [
        ("package-lock.json", FILE_J, ["pkg:npm/lodash@4.17.15", "pkg:npm/express@4.18.2", "pkg:npm/%40babel/core@7.23.0"]),
        ("go.mod", FILE_L, ["pkg:golang/github.com/gin-gonic/gin@v1.9.0", "pkg:golang/golang.org/x/text@v0.3.7",
                            "pkg:golang/github.com/gorilla/mux@v1.8.0"]),
        ("Cargo.lock", FILE_M, ["pkg:cargo/serde@1.0.100", "pkg:cargo/time@0.1.43"]),
        ("package.json", FILE_K, ["pkg:npm/lodash@4.17.15", "pkg:npm/express", "pkg:npm/left-pad", "pkg:npm/mocha@10.2.0"]),
    ]
    import datetime as d
    for i, (filename, content, purls) in enumerate(cases):
        c = make_client(clock=lambda i=i: d.datetime(2026, 11, 9, 10, 0, i, tzinfo=d.timezone(d.timedelta(hours=9))))
        body = send(c, filename, content, project=f"p{i}").json()
        doc = json.loads((data_dir / f"p{i}" / f"sbom-{body['scan_id']}.cdx.json").read_text(encoding="utf-8"))
        assert [x["purl"] for x in doc["components"]] == purls, filename
    # 확정 버전이 아닌 npm 항목은 version과 purl의 버전 없이 원문 표기를 properties에 둔다
    unpinned = {c["name"]: c for c in doc["components"]}  # 마지막(package.json) 문서
    assert "version" not in unpinned["express"]
    assert unpinned["express"]["properties"] == [{"name": "sbom-web:version-spec", "value": "^4.18.0"}]
    assert unpinned["left-pad"]["properties"][0]["value"] == "latest"


def test_history_and_downloads_work_for_the_new_file_kinds(make_client, client):
    body = send(make_client(FakeSource(SET_GO)), "go.mod", FILE_L).json()
    assert client.get(body["links"]["sbom"]).status_code == 200
    assert client.get(body["links"]["cyclonedx"]).status_code == 200
    scans = client.get("/api/projects/demo/scans").json()["scans"]
    assert [s["scan_id"] for s in scans] == [body["scan_id"]]


def test_large_lockfile_is_deduplicated_by_name_version_ecosystem(make_client):
    # 같은 패키지가 여러 위치에 설치된 잠금 파일: 조회는 (이름, 버전, 생태계)당 한 번
    packages = {"": {"name": "root"}}
    for i in range(30):
        packages[f"node_modules/dep{i}/node_modules/shared"] = {"version": "1.0.0"}
    packages["node_modules/shared"] = {"version": "1.0.0"}
    src = FakeSource()
    body = send(make_client(src), "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": packages}).encode()).json()
    assert body["collected"] == 31 and src.calls == [("shared", "1.0.0", "npm")]


# ================= 실제 OSV (OSV_LIVE_TEST=1일 때만) =================

LIVE = os.environ.get("OSV_LIVE_TEST") == "1"


def _live_client(data_dir):
    return TestClient(create_app(Settings(data_dir=data_dir)))  # 실제 OsvSource


@pytest.mark.skipif(not LIVE, reason="OSV_LIVE_TEST=1일 때만 실제 OSV 호출")
@pytest.mark.parametrize("filename,content,package", [
    ("package.json", b'{"dependencies": {"lodash": "4.17.15"}}', "lodash"),
    ("go.mod", b"module x\n\nrequire golang.org/x/text v0.3.7\n", "golang.org/x/text"),
    ("Cargo.lock", b'[[package]]\nname = "time"\nversion = "0.1.43"\n'
                   b'source = "registry+https://github.com/rust-lang/crates.io-index"\n', "time"),
])
def test_real_osv_finds_vulnerabilities_for_each_ecosystem(data_dir, filename, content, package):
    r = send(_live_client(data_dir), filename, content)
    body = r.json()
    assert r.status_code == 201, body
    assert body["vulnerabilities_total"] >= 1
    assert all(row["package"] == package for row in body["table"])


@pytest.mark.skipif(not LIVE, reason="OSV_LIVE_TEST=1일 때만 실제 OSV 호출")
def test_real_osv_go_version_prefix_does_not_change_results(data_dir):
    from app.osv import OsvSource
    src = OsvSource("https://api.osv.dev", 30)
    with_v = sorted(f.vuln_id for f in src.query("golang.org/x/text", "v0.3.7", "Go"))
    without = sorted(f.vuln_id for f in src.query("golang.org/x/text", "0.3.7", "Go"))
    assert with_v and with_v == without  # 그래서 원문(v 포함)을 그대로 보낸다


# ---- 사례 72: 읽을 수 없는 줄이 있는 go.mod (정상 줄은 건너뛴 줄이 아니다) ----

def test_case72_go_mod_counts_only_unreadable_lines(make_client, data_dir):
    raw = (b"module example.com/demo\n\ngo 1.21\n\n"
           b"require github.com/gin-gonic/gin v1.9.0\n"
           b"require (\n\tgolang.org/x/text v0.3.7 // indirect\n\tgithub.com/no/version\n)\n"
           b"replace github.com/gorilla/mux => ../mux\n"
           b"mystery-directive x y\n")
    src = FakeSource(SET_GO)
    r = send(make_client(src), "go.mod", raw)
    body = r.json()
    assert r.status_code == 201 and body["collected"] == 2
    assert body["skipped_lines"] == 2  # 버전 없는 require 항목, 알 수 없는 지시어. module, go, replace는 세지 않음
    assert sorted(src.calls) == [("github.com/gin-gonic/gin", "v1.9.0", "Go"), ("golang.org/x/text", "v0.3.7", "Go")]


# ---- 사례 73: 응답 표와 화면의 생태계 표시 (C21) ----

from app.osv import Finding  # noqa: E402


def test_case73_table_rows_carry_the_ecosystem_but_the_report_file_is_unchanged(make_client, data_dir):
    src = FakeSource({("left-pad", "1.0.0", "npm"): [Finding("TEST-X1", "높음")],
                      ("left-pad", "1.0.0", "PyPI"): [Finding("TEST-X2", "높음")]})
    c = make_client(src)
    body = send(c, "package.json", b'{"dependencies": {"left-pad": "1.0.0"}}').json()
    assert [(r["package"], r["ecosystem"]) for r in body["table"]] == [("left-pad", "npm")]
    other = send(c, "requirements.txt", b"left-pad==1.0.0\n", project="other").json()
    assert [(r["package"], r["ecosystem"], r["vuln_id"]) for r in other["table"]] == [("left-pad", "PyPI", "TEST-X2")]
    report = next((data_dir / "demo").glob("vuln-report-*.txt")).read_text(encoding="utf-8")
    assert "TEST-X1 left-pad 1.0.0" in report and "npm" not in report  # 보고서 항목 줄 형식은 그대로


def test_case73_screen_table_has_an_ecosystem_column_with_a_mobile_label():
    from pathlib import Path
    html = (Path(__file__).resolve().parent.parent / "app" / "static" / "index.html").read_text(encoding="utf-8")
    assert "<th>ecosystem</th>" in html and 'data-label="ecosystem"' in html and "esc(row.ecosystem)" in html
