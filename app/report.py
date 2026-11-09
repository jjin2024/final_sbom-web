"""보고서·표 구성 (R3-2): 정렬, 응답용 표 상위 N행, vuln-report 파일 내용."""
from dataclasses import dataclass
from datetime import datetime

from .clock import display_time
from .severity import RANK, UNKNOWN


@dataclass(frozen=True)
class VulnRow:
    package: str
    version: str
    vuln_id: str
    severity: str | None
    summary_status: str = ""  # T8에서 채움 (T3에서는 비워 둠)
    summary: str = ""


def sort_rows(rows: list[VulnRow]) -> list[VulnRow]:
    """심각도 높은 순(심각 > 높음 > 보통 > 낮음), 같으면 취약점 ID 순, 심각도 없음은 맨 뒤.
    요청마다 순서가 같도록 패키지와 버전으로 한 번 더 정렬한다."""
    return sorted(
        rows,
        key=lambda r: (RANK.get(r.severity, len(RANK)), r.vuln_id, r.package, r.version),
    )


def table_row(r: VulnRow) -> dict:
    return {
        "package": r.package,
        "version": r.version,
        "vuln_id": r.vuln_id,
        "severity": r.severity or UNKNOWN,
        "summary_status": r.summary_status,
        "summary": r.summary,
    }


def build_table(rows: list[VulnRow], max_rows: int) -> tuple[list[dict], int]:
    """정렬된 rows에서 상위 max_rows행과 생략한 건수."""
    shown = rows[:max_rows]
    return [table_row(r) for r in shown], len(rows) - len(shown)


def render_report(project: str, scan: str, t: datetime, rows: list[VulnRow]) -> str:
    lines = [
        "# 취약점 보고서",
        f"# 프로젝트: {project}",
        f"# 스캔 ID: {scan}",
        f"# 조회 시각: {display_time(t)}",
    ]
    if not rows:
        lines.append("발견된 취약점 없음")
    else:
        lines.append(f"## 취약점 {len(rows)}건 (심각도 순)")
        for r in rows:
            lines.append(f"{r.vuln_id} {r.package} {r.version} {r.severity or UNKNOWN}")
    return "\n".join(lines) + "\n"
