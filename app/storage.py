"""이력 저장소. 목록 파일(R2)과 보고서 파일(R3-2) 저장 (2.4의 파일 형식)."""
import os
from datetime import datetime
from pathlib import Path

from .clock import display_time, scan_id
from .parser import Package


class StorageError(Exception):
    """데이터 폴더에 쓸 수 없음 (API는 500 또는 경고로 변환)."""


def render_sbom(project: str, t: datetime, packages: list[Package]) -> str:
    lines = [
        "# SBOM 목록",
        f"# 프로젝트: {project}",
        f"# 실행 시각: {display_time(t)}",
    ]
    for p in packages:
        suffix = "" if p.pinned else " (확정 버전 아님)"
        lines.append(f"{p.name} {p.version} {p.ecosystem}{suffix}")
    return "\n".join(lines) + "\n"


def _write_atomic(folder: Path, filename: str, content: str) -> Path:
    """임시 파일에 쓴 뒤 이름을 바꿔서, 실패해도 불완전한 파일을 남기지 않는다.
    폴더를 이번에 새로 만들었다면 실패 시 폴더도 지운다."""
    path = folder / filename
    tmp = folder / f".{filename}.tmp"
    created_folder = not folder.exists()
    try:
        folder.mkdir(parents=True, exist_ok=True)
        tmp.write_text(content, encoding="utf-8", newline="\n")
        os.replace(tmp, path)
    except OSError as e:
        try:
            tmp.unlink(missing_ok=True)
            if created_folder:
                folder.rmdir()
        except OSError:
            pass
        raise StorageError(str(e)) from e
    return path


def save_sbom(data_dir: Path, project: str, t: datetime, packages: list[Package]) -> Path:
    return _write_atomic(
        data_dir / project, f"sbom-{scan_id(t)}.txt", render_sbom(project, t, packages)
    )


def save_report(data_dir: Path, project: str, t: datetime, content: str) -> Path:
    return _write_atomic(data_dir / project, f"vuln-report-{scan_id(t)}.txt", content)
