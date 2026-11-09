import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

from .fakes import FakeSource

# 3.1 테스트용 입력 파일
FILE_A = b"flask==3.0.0\nrequests==2.31.0\n"  # 30바이트 (사례 6)
FILE_B = b"flask>=2.0\nrequests==2.31.0\nclick\n"
FILE_C_EMPTY = b""
FILE_C_COMMENT = b"# empty\n"
FILE_D = b"flask==3.0.0\nrequests==2.31.0\ndjango==4.2.0\nclick==8.1.7\n"
FILE_E = FILE_A
FILE_F = (
    b"flask==3.0.0\nrequests==2.31.0\ndjango==4.2.0\nnumpy==1.24.0\npillow==9.5.0\n"
)
FILE_H = b"# web\nflask==3.0.0\n\n-r other.txt\ngit+https://github.com/x/y.git\nrequests==2.31.0\n"
FILE_I = b"flask==3.0.0\nrequests==2.31.0\nflask==3.0.0\n"


@pytest.fixture
def data_dir(tmp_path):
    return tmp_path / "data"


@pytest.fixture
def source():
    """따로 정하지 않으면 응답 세트 E(취약점 없음). 호출은 source.calls에 기록된다."""
    return FakeSource()


@pytest.fixture
def make_client(data_dir, source):
    def _make(vuln_source=None, clock=None, summary_source=None, **settings):
        kwargs = {"vuln_source": vuln_source or source}
        if clock:
            kwargs["clock"] = clock
        if summary_source is not None:  # 주지 않으면 키가 없는 상태(요약 건너뜀)
            kwargs["summary_source"] = summary_source
        return TestClient(create_app(Settings(data_dir=data_dir, **settings), **kwargs))

    return _make


@pytest.fixture
def client(make_client):
    return make_client()


def upload(client, project="demo", content=FILE_A, filename="requirements.txt"):
    return client.post(
        f"/api/projects/{project}/scans", files={"file": (filename, content)}
    )
