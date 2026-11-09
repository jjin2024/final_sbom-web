"""테스트용 가짜 취약점 DB (3.1의 고정 응답 세트). 어떤 요청이 몇 번 갔는지 기록한다."""
from app.osv import Finding, LookupFailed


class FakeSource:
    def __init__(self, responses=None, fail=False):
        self.responses = responses or {}
        self.fail = fail
        self.calls: list[tuple[str, str, str]] = []

    def query(self, name, version, ecosystem):
        self.calls.append((name, version, ecosystem))
        if self.fail:
            raise LookupFailed("blocked")
        return list(self.responses.get((name, version), []))


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
