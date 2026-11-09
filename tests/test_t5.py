"""T5(R6, R6-2)의 서버 쪽 확인. 화면 동작(사례 43, 44)은 브라우저(Playwright)로 따로 확인한다."""
import re
from pathlib import Path

INDEX = Path(__file__).parent.parent / "app" / "static" / "index.html"


def test_index_served_as_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert 'lang="ko"' in r.text
    assert 'id="project-name"' in r.text and 'type="file"' in r.text


def test_index_calls_the_documented_api_same_origin():
    text = INDEX.read_text(encoding="utf-8")
    assert "'/api/projects/'" in text and "/scans'" in text  # 상대 경로(같은 서버)
    assert "append('file'" in text  # 파일 필드 이름은 file
    assert "encodeURIComponent" in text  # 프로젝트 이름은 인코딩해서 경로에 넣음


def test_index_has_no_dash_characters_banned_by_design_rules():
    text = INDEX.read_text(encoding="utf-8")
    assert "—" not in text and "–" not in text


def test_index_escapes_server_strings_before_inserting_html():
    # 서버가 준 문자열은 esc()(textContent로 변환)를 거쳐서만 HTML에 들어간다.
    # 악성 문자열이 태그로 실행되지 않는 것은 Playwright로 확인했다(자동 테스트 아님).
    text = INDEX.read_text(encoding="utf-8")
    assert re.search(r"function esc\(v\)\{const e=document\.createElement\('span'\);e\.textContent=", text)
    for field in ["scan_id", "collected", "skipped_lines", "not_looked_up",
                  "vulnerabilities_total", "package", "version", "vuln_id", "severity",
                  "summary_status", "summary"]:
        assert re.search(rf"esc\((data|row)\.{field}\)", text), f"{field}가 esc() 없이 쓰이는지 확인 필요"


def test_index_inputs_have_connected_labels():
    text = INDEX.read_text(encoding="utf-8")
    for field in ["project-name", "package-file"]:
        assert f'id="{field}"' in text
        assert f'<label class="label" for="{field}">' in text


def test_index_has_no_demo_hook_and_no_fake_shortcuts():
    # 가짜 취약점 데이터를 보여 주는 ?demo= 매개변수와 동작하지 않는 단축키 안내는 두지 않는다
    text = INDEX.read_text(encoding="utf-8")
    assert "demo" not in text.lower()
    assert "F1" not in text and "ESC:" not in text


def test_index_text_is_at_least_12px():
    import re as _re
    style = INDEX.read_text(encoding="utf-8").split("<style>")[1].split("</style>")[0]
    sizes = [int(n) for n in _re.findall(r"font(?:-size)?:(?:bold )?(\d+)px", style)]
    assert sizes and min(sizes) >= 12


def test_index_has_no_external_resources():
    text = INDEX.read_text(encoding="utf-8")
    assert "http://" not in text and "https://" not in text
    assert "<script src" not in text and "<link rel=\"stylesheet\"" not in text
    assert "@import" not in text


def test_index_script_has_no_unbalanced_template_literals():
    # 문자열 안에 ${...}를 홑따옴표로 넣어 스크립트가 통째로 깨졌던 사고의 재발 방지
    script = INDEX.read_text(encoding="utf-8").split("<script>")[1].split("</script>")[0]
    assert "${'" not in script
