import re
from datetime import datetime
from pathlib import Path
from typing import Callable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.datastructures import UploadFile

from .clock import display_scan_time, now_kst, scan_id
from .compare import compare
from .cyclonedx import render as render_cyclonedx
from .config import Settings
from .osv import LookupFailed, OsvSource, VulnSource, query_many
from .parser import FormatError, Package, parse_upload
from .report import VulnRow, build_table, render_report, sort_rows
from .summary import GeminiSource, SummarySource, summarize_rows
from .storage import (
    ScanExists,
    StorageError,
    list_scans,
    previous_scan_id,
    save_cyclonedx,
    save_report,
    save_sbom,
    scan_file,
)

STATIC_DIR = Path(__file__).parent / "static"
PROJECT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$")
NAME_RULE_MESSAGE = (
    "프로젝트 이름 규칙 위반: 영문, 숫자, '.', '_', '-'만 쓰고 영문 또는 숫자로 시작하는 1~50자"
)


def links_for(project: str, sid: str, has_report: bool, has_cyclonedx: bool = False) -> dict:
    """내려받기 경로. 파일이 없으면 null(보고서가 없는 스캔, CycloneDX 파일이 없는 과거 스캔 등)."""
    base = f"/api/projects/{project}/scans/{sid}"
    return {
        "sbom": f"{base}/sbom",
        "report": f"{base}/report" if has_report else None,
        "cyclonedx": f"{base}/cyclonedx" if has_cyclonedx else None,
    }


def error(status: int, message: str, **extra) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message, **extra})


def lookup_targets(packages: list[Package]) -> list[tuple[str, str, str]]:
    """확정 버전 항목만, (이름, 버전, 생태계)가 같으면 한 번만 (R3)."""
    seen: dict[tuple[str, str, str], None] = {}
    for p in packages:
        if p.pinned:
            seen.setdefault((p.name, p.version, p.ecosystem), None)
    return list(seen)


def create_app(
    settings: Settings | None = None,
    clock: Callable[[], datetime] = now_kst,
    vuln_source: VulnSource | None = None,
    summary_source: SummarySource | None = None,
) -> FastAPI:
    """clock, vuln_source, summary_source는 테스트에서 고정 값과 가짜 응답으로 바꿔 끼운다 (3.1).
    summary_source를 주지 않으면 API 키(환경 변수 GEMINI_API_KEY)가 있을 때만 Gemini를 쓰고,
    키가 없으면 요약을 건너뛴다 (R4)."""
    settings = settings or Settings.from_env()
    vuln_source = vuln_source or OsvSource(settings.osv_url, settings.external_timeout)
    if summary_source is None and settings.gemini_api_key:
        summary_source = GeminiSource(
            settings.gemini_api_key,
            settings.gemini_url,
            settings.gemini_model,
            settings.gemini_timeout,
            settings.gemini_max_output_tokens,
            settings.gemini_thinking_level,
        )
    app = FastAPI()

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # FastAPI 기본 422 대신 400으로 응답한다 (4.3)
        return error(400, "요청 형식이 올바르지 않음")

    # {project:path}: `..%2Fx`처럼 `/`로 디코딩되는 이름도 이 함수에 도달해
    # 404가 아닌 400(이름 규칙 위반)으로 처리하기 위함
    @app.post("/api/projects/{project:path}/scans")
    async def create_scan(project: str, request: Request):
        # 검증 순서: 이름 -> 파일 유무 -> 크기 -> 텍스트 -> 해석. 통과 전에는 아무것도 만들지 않는다.
        if not PROJECT_NAME.fullmatch(project):
            return error(400, NAME_RULE_MESSAGE)
        form = await request.form()
        upload = form.get("file")
        if not isinstance(upload, UploadFile):
            return error(400, "파일 없음: 'file' 필드로 파일을 올려 주세요")
        limit = settings.upload_max_bytes
        raw = await upload.read(limit + 1)
        if len(raw) > limit:
            return error(413, f"파일이 너무 큼: 업로드 크기 상한은 {limit}바이트")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            return error(400, "텍스트 파일이 아님: UTF-8로 읽을 수 없음")

        # 파일 이름이 package-lock.json, package.json, go.mod, Cargo.lock이면 그 형식으로, 아니면
        # requirements.txt 형식으로 해석한다. 지원하는 이름인데 내용이 맞지 않으면 400(아무것도 저장하지 않음).
        try:
            result = parse_upload(upload.filename, text)
        except FormatError as e:
            return error(400, str(e))
        if not result.packages:
            return error(400, "패키지를 찾을 수 없음")

        t = clock()  # 요청 시각은 한 번만 정한다
        sid = scan_id(t)

        # 이전 실행 대비 (R2-4): 같은 프로젝트에서 이번 요청보다 이른 것 중 가장 늦은 목록과 비교한다.
        # 직전 파일을 읽을 수 없으면 비교만 건너뛰고 이후 단계는 계속한다.
        prev_id = previous_scan_id(settings.data_dir, project, sid)
        prev_path = settings.data_dir / project / f"sbom-{prev_id}.txt" if prev_id else None
        comparison = compare(prev_id, prev_path, result.packages)

        try:
            save_sbom(settings.data_dir, project, t, result.packages, comparison.lines())
        except ScanExists:
            # 같은 시각(초)의 스캔이 있음: 기존 파일을 덮어쓰지 않고 이후 단계(조회 등)를 진행하지 않는다 (R2-3)
            return error(409, "같은 시각의 스캔이 있음: 잠시 후 다시 요청해 주세요")
        except StorageError:
            return error(500, "저장 실패: 결과 파일을 저장할 수 없음")

        # CycloneDX 파일 (R2-5): 목록 파일을 저장한 뒤 같은 스캔 ID로 만든다. 실패해도 목록 파일과
        # 보고서는 정상이고 요청은 201이며, 경고만 담는다(불완전한 파일은 남지 않는다).
        warnings: list[str] = []
        cdx_saved = True
        try:
            save_cyclonedx(
                settings.data_dir, project, t, render_cyclonedx(project, t, result.packages)
            )
        except StorageError:
            cdx_saved = False
            warnings.append("CycloneDX 파일 저장 실패")

        # 취약점 조회. 하나라도 실패하면 조회를 중단한다 (R3-3).
        # 목록 파일은 이미 저장되어 있고, 이 요청의 보고서는 만들지 않으며, 요약 호출도 하지 않는다.
        targets = lookup_targets(result.packages)
        try:
            found = query_many(vuln_source, targets, settings.lookup_workers)
        except LookupFailed:
            # 실패 원인(주소, 응답 내용)은 응답에 넣지 않는다
            return error(
                502,
                "조회 실패, 목록은 저장됨: 취약점 DB(OSV)를 조회하지 못했습니다. "
                "잠시 후 다시 시도해 주세요.",
                scan_id=scan_id(t),
            )
        rows = sort_rows([
            VulnRow(name, version, f.vuln_id, f.severity, ecosystem=eco)
            for (name, version, eco), findings in zip(targets, found)
            for f in findings
        ])

        # AI 요약 (R4): 심각도 높은 순으로 최대 N건을 묶음으로 요약한다. 요약 실패 처리(R4-2)는 T9.
        outcome = summarize_rows(
            rows, summary_source, settings.summary_max_items, settings.summary_batch_size
        )
        rows = outcome.rows
        table, omitted = build_table(rows, settings.table_max_rows)
        summary_line = outcome.aggregate if outcome.attempted else outcome.skip_message

        report_saved = True
        try:
            save_report(
                settings.data_dir, project, t, render_report(project, sid, t, rows, summary_line)
            )
        except StorageError:
            report_saved = False
            warnings.append("보고서 파일 저장 실패")

        content = {
            "scan_id": sid,
            "collected": len(result.packages),
            "skipped_lines": result.skipped_lines,
            "not_looked_up": result.not_looked_up,
            "comparison": comparison.to_json(),
            "vulnerabilities_total": len(rows),
            "table": table,
            "table_omitted": omitted,
            "warnings": warnings,
            "links": links_for(project, sid, report_saved, cdx_saved),
            "summary": outcome.to_json(),
        }
        if not rows:
            content["message"] = "발견된 취약점 없음"
        elif omitted:
            content["message"] = f"외 {omitted}건은 보고서 참조"
        return JSONResponse(status_code=201, content=content)

    def download(project: str, sid: str, kind: str):
        if not PROJECT_NAME.fullmatch(project):
            return error(400, NAME_RULE_MESSAGE)
        path = scan_file(settings.data_dir, project, sid, kind)
        if path is None:
            what = {"sbom": "목록 파일", "report": "보고서", "cyclonedx": "CycloneDX 파일"}[kind]
            return error(404, f"{what}을 찾을 수 없음")
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return error(500, "파일을 읽을 수 없음")
        media = "application/json" if kind == "cyclonedx" else "text/plain; charset=utf-8"
        return Response(
            content=text,
            media_type=media,
            headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
        )

    # 더 구체적인 경로를 먼저 등록한다
    @app.get("/api/projects/{project:path}/scans/{sid}/sbom")
    async def get_sbom(project: str, sid: str):
        return download(project, sid, "sbom")

    @app.get("/api/projects/{project:path}/scans/{sid}/report")
    async def get_report(project: str, sid: str):
        return download(project, sid, "report")

    @app.get("/api/projects/{project:path}/scans/{sid}/cyclonedx")
    async def get_cyclonedx(project: str, sid: str):
        return download(project, sid, "cyclonedx")

    @app.get("/api/projects/{project:path}/scans")
    async def list_project_scans(project: str):
        if not PROJECT_NAME.fullmatch(project):
            return error(400, NAME_RULE_MESSAGE)
        try:
            scans = list_scans(settings.data_dir, project)
        except StorageError:
            return error(500, "이력을 읽을 수 없음")
        return {  # 이력이 없는 프로젝트는 빈 목록(200)
            "project": project,
            "scans": [
                {
                    "scan_id": s.scan_id,
                    "time": display_scan_time(s.scan_id),
                    "has_report": s.has_report,
                    "links": links_for(project, s.scan_id, s.has_report, s.has_cyclonedx),
                }
                for s in scans
            ],
        }

    return app


app = create_app()
