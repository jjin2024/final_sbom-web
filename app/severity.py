"""OSV 심각도 정보를 등급(심각, 높음, 보통, 낮음)으로 바꾼다 (4.5 확인 결과).

우선순위:
1. 데이터 출처가 준 문자열 등급 (GHSA의 database_specific.severity)
2. CVSS v3.x 벡터 문자열의 기본 점수 계산
3. 그 외(CVSS v4 벡터뿐인 경우 등)는 None -> 표에는 "알 수 없음"
"""
import math

CRITICAL, HIGH, MEDIUM, LOW = "심각", "높음", "보통", "낮음"
UNKNOWN = "알 수 없음"
RANK = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}

_TEXT = {
    "CRITICAL": CRITICAL,
    "HIGH": HIGH,
    "MODERATE": MEDIUM,
    "MEDIUM": MEDIUM,
    "LOW": LOW,
}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def from_text(value: str | None) -> str | None:
    return _TEXT.get((value or "").strip().upper())


def _roundup(x: float) -> float:
    """CVSS v3.1 부록 A의 Roundup."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    parts = vector.split("/")
    if not parts or not parts[0].startswith("CVSS:3"):
        return None
    try:
        m = dict(p.split(":", 1) for p in parts[1:])
        changed = {"U": False, "C": True}[m["S"]]
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except (KeyError, ValueError):
        return None
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    total = impact + expl
    return _roundup(min(1.08 * total if changed else total, 10))


def from_score(score: float) -> str | None:
    if score <= 0:
        return None
    if score >= 9.0:
        return CRITICAL
    if score >= 7.0:
        return HIGH
    if score >= 4.0:
        return MEDIUM
    return LOW


def from_vectors(vectors: list[str]) -> str | None:
    """CVSS v3 벡터가 여럿이면 가장 높은 점수를 쓴다."""
    scores = [s for s in (cvss3_score(v) for v in vectors) if s is not None]
    return from_score(max(scores)) if scores else None
