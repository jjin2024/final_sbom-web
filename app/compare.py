"""이전 실행 대비 (R2-4): (패키지명, 생태계)를 기준으로 추가, 삭제, 버전 변경, 변경 없음을 센다."""
from dataclasses import dataclass, field
from pathlib import Path

from .parser import Package
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


def _group(entries: list[Item]) -> dict[tuple[str, str], list[str]]:
    """(이름, 생태계) -> 버전 표기들. 같은 줄이 여러 번 나와도 한 번만 센다."""
    groups: dict[tuple[str, str], list[str]] = {}
    for name, version, eco in entries:
        versions = groups.setdefault((name, eco), [])
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
    for (name, eco), versions in new.items():
        if (name, eco) not in old:
            result.added.append((name, ", ".join(versions), eco))
        elif set(versions) == set(old[(name, eco)]):
            result.unchanged += 1
        else:
            result.changed.append((name, ", ".join(old[(name, eco)]), ", ".join(versions), eco))
    for (name, eco), versions in old.items():
        if (name, eco) not in new:
            result.removed.append((name, ", ".join(versions), eco))
    return result
