"""테스트용 가짜 취약점 DB (3.1의 고정 응답 세트). 어떤 요청이 몇 번 갔는지 기록한다."""
from app.osv import Finding, LookupFailed


class FakeSummary:
    """테스트용 가짜 Gemini. 어떤 요청(묶음)이 몇 번 갔는지 기록한다."""

    def __init__(self, fail_calls=(), fatal_calls=()):
        self.calls: list[list] = []  # 호출마다 SummaryItem 목록
        self.fail_calls = set(fail_calls)  # 실패시킬 호출 번호(1부터). HTTP 500처럼 이후 묶음은 계속 시도
        self.fatal_calls = set(fatal_calls)  # HTTP 429처럼 남은 묶음을 중단시키는 실패

    def summarize(self, items):
        from app.summary import SummaryFailed
        self.calls.append(list(items))
        if len(self.calls) in self.fatal_calls:
            raise SummaryFailed("HTTP 429", fatal=True)
        if len(self.calls) in self.fail_calls:
            raise SummaryFailed("HTTP 500")
        return [f"요약:{i.vuln_id}" for i in items]


class FakeSource:
    def __init__(self, responses=None, fail=False, fail_for=()):
        self.responses = responses or {}
        self.fail = fail  # 모든 조회 실패 (연결 차단)
        self.fail_for = set(fail_for)  # 이 (이름, 버전)만 실패
        self.calls: list[tuple[str, str, str]] = []

    def query(self, name, version, ecosystem):
        self.calls.append((name, version, ecosystem))
        if self.fail or (name, version) in self.fail_for:
            raise LookupFailed("blocked: secret-host.internal:443")
        # (이름, 버전, 생태계)로 먼저 찾고, 없으면 (이름, 버전)으로 찾는다
        found = self.responses.get((name, version, ecosystem), self.responses.get((name, version), []))
        return list(found)


# 심각도는 심각 > 높음 > 보통 > 낮음
SET_E = {}  # 모든 패키지: 취약점 없음
SET_D = {
    ("flask", "3.0.0"): [Finding("TEST-0001", "높음")],
    ("requests", "2.31.0"): [Finding("TEST-0002", "보통")],
    ("django", "4.2.0"): [Finding("TEST-0003", "낮음")],
    ("click", "8.1.7"): [],
}
SET_F = {
    ("flask", "3.0.0"): [Finding("TEST-0001", "심각")],
    ("requests", "2.31.0"): [Finding("TEST-0002", "높음")],
    ("django", "4.2.0"): [Finding("TEST-0003", "보통")],
    ("numpy", "1.24.0"): [Finding("TEST-0004", "낮음")],
    ("pillow", "9.5.0"): [Finding("TEST-0005", "낮음")],
}


def many(n: int, package=("flask", "3.0.0")):
    """취약점 n건이 나오는 고정 응답 (사례 28, 33, 36). 심각도는 돌아가며 부여한다."""
    levels = ["낮음", "보통", "높음", "심각"]
    return {package: [Finding(f"TEST-{i:04d}", levels[i % 4]) for i in range(1, n + 1)]}


# T12: 생태계별 응답 세트 (키는 (이름, 버전, 생태계))
SET_NPM = {
    ("lodash", "4.17.15", "npm"): [Finding("TEST-N001", "높음")],
    ("express", "4.18.2", "npm"): [],
    ("@babel/core", "7.23.0", "npm"): [Finding("TEST-N002", "보통")],
    ("mocha", "10.2.0", "npm"): [],
}
SET_GO = {
    ("github.com/gin-gonic/gin", "v1.9.0", "Go"): [Finding("TEST-G001", "심각")],
    ("golang.org/x/text", "v0.3.7", "Go"): [Finding("TEST-G002", "높음")],
    ("github.com/gorilla/mux", "v1.8.0", "Go"): [],
}
SET_RUST = {
    ("serde", "1.0.100", "crates.io"): [Finding("TEST-R001", "낮음")],
    ("time", "0.1.43", "crates.io"): [Finding("TEST-R002", "높음")],
}
