"""T5(R6, R6-2)의 서버 쪽 확인. 화면 동작(사례 43, 44)은 브라우저(Playwright)로 따로 확인한다."""
from pathlib import Path

INDEX = Path(__file__).parent.parent / "app" / "static" / "index.html"


def test_index_served_as_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert 'lang="ko"' in r.text
    assert 'name="file"' in r.text and 'id="project"' in r.text


def test_index_has_no_dash_characters_banned_by_design_rules():
    text = INDEX.read_text(encoding="utf-8")
    assert "—" not in text and "–" not in text


def test_index_does_not_use_innerhtml_for_server_data():
    # 서버가 준 문자열은 textContent로만 넣는다
    assert "innerHTML" not in INDEX.read_text(encoding="utf-8")


def test_index_has_no_external_resources():
    text = INDEX.read_text(encoding="utf-8")
    assert "http://" not in text and "https://" not in text
