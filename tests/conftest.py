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

# T12: 다른 언어의 의존성 파일 (개발 문서 3.1의 J~P)
FILE_J = b"""{
  "name": "demo-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "demo-app", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}},
    "node_modules/lodash": {"version": "4.17.15"},
    "node_modules/express": {"version": "4.18.2"},
    "node_modules/@babel/core": {"version": "7.23.0"},
    "node_modules/shared-lib": {"resolved": "../shared-lib", "link": true}
  }
}
"""  # package-lock.json: 루트 1, 일반 2, @scope/name 1, link 1
FILE_K = b"""{
  "name": "demo-app",
  "dependencies": {"lodash": "4.17.15", "express": "^4.18.0", "left-pad": "latest"},
  "devDependencies": {"mocha": "10.2.0"}
}
"""  # package.json: 정확한 버전 1, ^ 범위 1, latest 1, devDependencies 1
FILE_L = (
    b"module example.com/demo\n"
    b"\n"
    b"go 1.21\n"
    b"\n"
    b"require github.com/gin-gonic/gin v1.9.0\n"
    b"\n"
    b"require (\n"
    b"\tgolang.org/x/text v0.3.7 // indirect\n"
    b"\tgithub.com/gorilla/mux v1.8.0\n"
    b")\n"
    b"\n"
    b"replace github.com/gorilla/mux => ../mux\n"
)  # go.mod: 한 줄 require, 블록 require(// indirect 포함), replace 줄 1
FILE_M = b"""version = 3

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef"

[[package]]
name = "time"
version = "0.1.43"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "fedcba9876543210"
"""  # Cargo.lock: registry 패키지 2, source 없는 자기 자신 1
FILE_N = b'{"packages": {"node_modules/lodash": {"version": "4.17.15"'  # 구문 오류가 있는 JSON
FILE_O = b"""{
  "name": "old-app",
  "lockfileVersion": 1,
  "dependencies": {"lodash": {"version": "4.17.15"}}
}
"""  # lockfileVersion 1: packages 없음
FILE_P = b'[[package]]\nname = "serde\nversion = 1.0'  # 구문 오류가 있는 TOML


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
