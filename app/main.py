import re
from datetime import datetime
from typing import Callable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.datastructures import UploadFile

from .clock import now_kst, scan_id
from .config import Settings
from .osv import OsvSource, VulnSource
from .parser import Package, parse_requirements
from .report import VulnRow, build_table, render_report, sort_rows
from .storage import StorageError, save_report, save_sbom

PROJECT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$")


def error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message})


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
) -> FastAPI:
    """clock과 vuln_source는 테스트에서 고정 값과 가짜 응답으로 바꿔 끼운다 (3.1)."""
    settings = settings or Settings.from_env()
    vuln_source = vuln_source or OsvSource(settings.osv_url, settings.external_timeout)
    app = FastAPI()

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
            return error(
                400,
                "프로젝트 이름 규칙 위반: 영문, 숫자, '.', '_', '-'만 쓰고 "
                "영문 또는 숫자로 시작하는 1~50자",
            )
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

        result = parse_requirements(text)
        if not result.packages:
            return error(400, "패키지를 찾을 수 없음")

        t = clock()  # 요청 시각은 한 번만 정한다
        try:
            save_sbom(settings.data_dir, project, t, result.packages)
        except StorageError:
            return error(500, "저장 실패: 결과 파일을 저장할 수 없음")

        # 취약점 조회. 조회 실패 처리(502)는 T6에서 추가한다.
        rows: list[VulnRow] = []
        for name, version, eco in lookup_targets(result.packages):
            for f in vuln_source.query(name, version, eco):
                rows.append(VulnRow(name, version, f.vuln_id, f.severity))
        rows = sort_rows(rows)
        table, omitted = build_table(rows, settings.table_max_rows)

        warnings: list[str] = []
        try:
            save_report(
                settings.data_dir, project, t, render_report(project, scan_id(t), t, rows)
            )
        except StorageError:
            warnings.append("보고서 파일 저장 실패")

        content = {
            "scan_id": scan_id(t),
            "collected": len(result.packages),
            "skipped_lines": result.skipped_lines,
            "not_looked_up": result.not_looked_up,
            "vulnerabilities_total": len(rows),
            "table": table,
            "table_omitted": omitted,
            "warnings": warnings,
        }
        if not rows:
            content["message"] = "발견된 취약점 없음"
            content["summary"] = {"skipped_reason": "요약할 취약점 없음"}
        elif omitted:
            content["message"] = f"외 {omitted}건은 보고서 참조"
        return JSONResponse(status_code=201, content=content)

    return app


app = create_app()
