"""이전 실행 대비 (R2-4): (패키지명, 생태계)를 기준으로 추가, 삭제, 버전 변경, 변경 없음을 센다.

비교 키를 만들 때만 PyPI 이름을 PEP 503 규칙으로 정규화한다(소문자, `-` `_` `.`의 연속을 `-` 하나로).
npm, Go, Rust 이름은 정규화하지 않는다. 화면과 파일에는 새 요청의 원문 이름을 쓴다(없어진 항목은 이전 파일의 이름).
"""
import re
from dataclasses import dataclass, field
from pathlib import Path

from .parser import ECO_PYPI, Package
from .storage import UnreadableSbom, read_sbom_entries

NO_BASELINE = "비교 대상 없음"
SKIPPED = "비교 건너뜀"
COMPARED = "비교함"
SKIP_MESSAGE = "비교 건너뜀(직전 파일을 읽을 수 없음)"

Item = tuple[str, str, str]  # (이름, 버전, 생태계)


@dataclass
class Comparison:
    status: str
    previous: str | None = None  # 직전 스캔 ID
    added: list[Item] = field(default_factory=list)
    removed: list[Item] = field(default_factory=list)
    changed: list[tuple[str, str, str, str]] = field(default_factory=list)  # 이름, 이전, 이후, 생태계
    unchanged: int = 0

    def lines(self) -> list[str]:
        """목록 파일 끝의 "이전 실행 대비" 구역. 응답의 lines와 같은 내용이다."""
        if self.status == NO_BASELINE:
            return ["## 이전 실행 대비", NO_BASELINE]
        header = f"## 이전 실행 대비 (직전: sbom-{self.previous}.txt)"
        if self.status == SKIPPED:
            return [header, SKIP_MESSAGE]

        def line(label: str, items: list[str]) -> str:
            return f"{label} {len(items)}" + (": " + ", ".join(items) if items else "")

        return [
            header,
            line("추가", [f"{n} {v} {e}" for n, v, e in self.added]),
            line("삭제", [f"{n} {v} {e}" for n, v, e in self.removed]),
            line("변경", [f"{n} {a} -> {b} {e}" for n, a, b, e in self.changed]),
            f"변경 없음 {self.unchanged}",
        ]

    def to_json(self) -> dict:
        return {
            "status": self.status,
            "previous_scan_id": self.previous,
            "message": SKIP_MESSAGE if self.status == SKIPPED else None,
            "added": [{"name": n, "version": v, "ecosystem": e} for n, v, e in self.added],
            "removed": [{"name": n, "version": v, "ecosystem": e} for n, v, e in self.removed],
            "changed": [
                {"name": n, "from": a, "to": b, "ecosystem": e} for n, a, b, e in self.changed
            ],
            "unchanged": self.unchanged,
            "lines": self.lines(),
        }


_PEP503 = re.compile(r"[-_.]+")


def _key(name: str, eco: str) -> tuple[str, str]:
    """비교 키. PyPI만 이름을 정규화한다(Flask_Login, flask-login, flask.login은 같은 패키지)."""
    return (_PEP503.sub("-", name).lower() if eco == ECO_PYPI else name, eco)


def _group(entries: list[Item]) -> dict[tuple[str, str], tuple[str, list[str]]]:
    """비교 키 -> (처음 나온 원문 이름, 버전 표기들). 같은 줄이 여러 번 나와도 한 번만 센다."""
    groups: dict[tuple[str, str], tuple[str, list[str]]] = {}
    for name, version, eco in entries:
        _shown, versions = groups.setdefault(_key(name, eco), (name, []))
        if version not in versions:
            versions.append(version)
    return groups


def compare(previous_id: str | None, previous_path: Path | None, packages: list[Package]) -> Comparison:
    if previous_id is None or previous_path is None:
        return Comparison(NO_BASELINE)
    try:
        old = _group(read_sbom_entries(previous_path))
    except UnreadableSbom:
        return Comparison(SKIPPED, previous=previous_id)  # 비교만 건너뛰고 이후 단계는 계속한다

    new = _group([(p.name, p.version, p.ecosystem) for p in packages])
    result = Comparison(COMPARED, previous=previous_id)
    for key, (name, versions) in new.items():  # name은 새 요청의 원문 이름
        eco = key[1]
        if key not in old:
            result.added.append((name, ", ".join(versions), eco))
        elif set(versions) == set(old[key][1]):
            result.unchanged += 1  # 이름 표기만 다르고 버전이 같으면 변경 없음
        else:
            result.changed.append((name, ", ".join(old[key][1]), ", ".join(versions), eco))
    for key, (name, versions) in old.items():  # 없어진 항목은 이전 파일의 이름
        if key not in new:
            result.removed.append((name, ", ".join(versions), key[1]))
    return result
