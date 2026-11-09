"""이력 저장소. 목록 파일(R2)과 보고서 파일(R3-2) 저장, 이력 조회(R2-2), 직전 목록 탐색(R2-4)."""
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .clock import display_time, scan_id
from .parser import Package

SCAN_ID = re.compile(r"^\d{8}-\d{6}$")
SBOM_FILE = re.compile(r"^sbom-(\d{8}-\d{6})\.txt$")
SBOM_HEADER = "# SBOM 목록"
UNPINNED_SUFFIX = " (확정 버전 아님)"
SECTION_PREFIX = "##"  # 목록 파일 끝의 "이전 실행 대비" 구역


class StorageError(Exception):
    """데이터 폴더에 쓸 수 없음 (API는 500 또는 경고로 변환)."""


class ScanExists(Exception):
    """같은 시각(초)의 스캔 파일이 이미 있음. 기존 파일은 덮어쓰지 않는다 (R2-3)."""


class UnreadableSbom(Exception):
    """직전 목록 파일을 읽거나 해석할 수 없음 (R2-4)."""


@dataclass(frozen=True)
class ScanInfo:
    scan_id: str
    has_report: bool
    has_cyclonedx: bool = False


def render_sbom(
    project: str, t: datetime, packages: list[Package], comparison_lines: list[str] | None = None
) -> str:
    lines = [
        SBOM_HEADER,
        f"# 프로젝트: {project}",
        f"# 실행 시각: {display_time(t)}",
    ]
    for p in packages:
        suffix = "" if p.pinned else UNPINNED_SUFFIX
        lines.append(f"{p.name} {p.version} {p.ecosystem}{suffix}")
    lines += comparison_lines or []
    return "\n".join(lines) + "\n"


def _cleanup(tmp: Path, folder: Path, created_folder: bool) -> None:
    try:
        tmp.unlink(missing_ok=True)
        if created_folder:
            folder.rmdir()
    except OSError:
        pass


def _write_atomic(folder: Path, filename: str, content: str, exclusive: bool = False) -> Path:
    """임시 파일에 쓴 뒤 이름을 바꿔서, 실패해도 불완전한 파일을 남기지 않는다.
    exclusive이면 같은 이름의 파일이 이미 있을 때 덮어쓰지 않고 ScanExists를 낸다.
    폴더를 이번에 새로 만들었다면 실패 시 폴더도 지운다."""
    path = folder / filename
    tmp = folder / f".{filename}.{uuid.uuid4().hex}.tmp"  # 동시 요청끼리 임시 파일이 겹치지 않게
    created_folder = not folder.exists()
    try:
        folder.mkdir(parents=True, exist_ok=True)
        tmp.write_text(content, encoding="utf-8", newline="\n")
        if exclusive:
            try:
                os.link(tmp, path)  # 이미 있으면 FileExistsError: 한 번에 확인하고 만든다
                tmp.unlink()
            except FileExistsError as e:
                raise ScanExists(filename) from e
            except OSError:
                # 하드링크를 지원하지 않는 파일 시스템(일부 바인드 마운트 등): 확인 후 이름 바꾸기
                if path.exists():
                    raise ScanExists(filename)
                os.replace(tmp, path)
        else:
            os.replace(tmp, path)
    except ScanExists:
        _cleanup(tmp, folder, False)
        raise
    except OSError as e:
        _cleanup(tmp, folder, created_folder)
        raise StorageError(str(e)) from e
    return path


def save_sbom(
    data_dir: Path,
    project: str,
    t: datetime,
    packages: list[Package],
    comparison_lines: list[str] | None = None,
) -> Path:
    folder = data_dir / project
    sid = scan_id(t)
    if (folder / f"vuln-report-{sid}.txt").exists():
        raise ScanExists(sid)  # 보고서만 남아 있어도 같은 스캔 ID로 보고 덮어쓰지 않는다
    return _write_atomic(
        folder, f"sbom-{sid}.txt", render_sbom(project, t, packages, comparison_lines), exclusive=True
    )


def save_report(data_dir: Path, project: str, t: datetime, content: str) -> Path:
    return _write_atomic(data_dir / project, f"vuln-report-{scan_id(t)}.txt", content)


def save_cyclonedx(data_dir: Path, project: str, t: datetime, content: str) -> Path:
    """CycloneDX 파일은 같은 요청의 목록 파일(`sbom-<시각>.txt`)과 같은 스캔 ID를 쓴다. 목록 파일을 먼저 저장한 뒤에 호출한다."""
    return _write_atomic(data_dir / project, f"sbom-{scan_id(t)}.cdx.json", content)


def list_scans(data_dir: Path, project: str) -> list[ScanInfo]:
    """프로젝트의 스캔을 최신순으로. 폴더가 없으면 빈 목록."""
    try:
        names = set(os.listdir(data_dir / project))
    except FileNotFoundError:
        return []
    except OSError as e:
        raise StorageError(str(e)) from e
    ids = sorted((m.group(1) for n in names if (m := SBOM_FILE.match(n))), reverse=True)
    # 스캔은 정확히 `sbom-<시각>.txt`로만 찾는다. `sbom-<시각>.cdx.json`은 같은 스캔의 부속 파일이라 스캔으로 세지 않는다.
    return [
        ScanInfo(i, f"vuln-report-{i}.txt" in names, f"sbom-{i}.cdx.json" in names) for i in ids
    ]


def previous_scan_id(data_dir: Path, project: str, current_id: str) -> str | None:
    """파일명의 시각이 이번 요청보다 이른 것 중 가장 늦은 스캔 (R2-4)."""
    try:
        earlier = [s.scan_id for s in list_scans(data_dir, project) if s.scan_id < current_id]
    except StorageError:
        return None
    return earlier[0] if earlier else None  # list_scans가 최신순이라 첫 항목이 가장 늦은 것


def read_sbom_entries(path: Path) -> list[tuple[str, str, str]]:
    """목록 파일의 (이름, 버전, 생태계). 읽을 수 없거나 형식이 다르면 UnreadableSbom."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        raise UnreadableSbom(str(e)) from e
    lines = text.splitlines()
    if not lines or lines[0].strip() != SBOM_HEADER:
        raise UnreadableSbom("header")
    entries: list[tuple[str, str, str]] = []
    for raw in lines[1:]:
        line = raw.strip()
        if line.startswith(SECTION_PREFIX):
            break  # 이전 실행 대비 구역부터는 항목이 아니다
        if not line or line.startswith("#"):
            continue
        parts = line.removesuffix(UNPINNED_SUFFIX).split(" ")
        if len(parts) != 3:
            raise UnreadableSbom("line")
        entries.append((parts[0], parts[1], parts[2]))
    if not entries:
        raise UnreadableSbom("empty")
    return entries


def scan_file(data_dir: Path, project: str, sid: str, kind: str) -> Path | None:
    """내려받기용 파일 경로. 스캔 ID 형식이 아니거나 파일이 없으면 None (R2-2)."""
    if not SCAN_ID.fullmatch(sid):
        return None  # 경로를 바꾸는 문자를 파일 이름에 쓰지 않는다
    filename = {
        "sbom": f"sbom-{sid}.txt",
        "report": f"vuln-report-{sid}.txt",
        "cyclonedx": f"sbom-{sid}.cdx.json",
    }[kind]
    path = data_dir / project / filename
    return path if path.is_file() else None
