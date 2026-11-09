"""T4(R5)의 서버 쪽 확인. 사례 40~42의 컨테이너 시험은 docker로 따로 실행한다."""


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
