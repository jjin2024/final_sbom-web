"""표준 SBOM 형식 CycloneDX 1.5 JSON 만들기 (R2-5).

업로드한 의존성 목록에서 구성요소(components) 목록을 만든다. 취약점 정보는 넣지 않는다(보고서가 따로 있음).
같은 요청이면 항상 같은 내용이 나오도록 serialNumber는 프로젝트와 스캔 ID로 만든 uuid5이다.
"""
import json
import re
import uuid
from datetime import datetime
from urllib.parse import quote

from .clock import KST, scan_id
from .parser import ECO_CRATES, ECO_GO, ECO_NPM, ECO_PYPI, Package

TOOL_NAME = "sbom-web"
SPEC_VERSION = "1.5"
VERSION_SPEC_PROPERTY = "sbom-web:version-spec"
_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "sbom-web")


def _q(text: str) -> str:
    """purl 구성요소 하나를 퍼센트 인코딩한다(`@`은 `%40`, `+`는 `%2B`). 슬래시는 호출한 쪽이 나눈다."""
    return quote(text, safe="")


def purl(ecosystem: str, name: str, version: str | None) -> str:
    """생태계별 Package URL. version이 None이면 `@버전`을 붙이지 않는다(확정 버전이 아닌 항목)."""
    if ecosystem == ECO_PYPI:
        kind, path = "pypi", _q(re.sub(r"[-_.]+", "-", name).lower())  # PEP 503 정규화
    elif ecosystem == ECO_NPM:
        kind = "npm"
        if name.startswith("@") and "/" in name:  # 스코프 패키지: pkg:npm/%40scope/name
            scope, rest = name.split("/", 1)
            path = f"{_q(scope)}/{_q(rest)}"
        else:
            path = _q(name)
    elif ecosystem == ECO_GO:
        kind, path = "golang", "/".join(_q(seg) for seg in name.split("/"))  # 모듈 경로의 슬래시는 유지
    elif ecosystem == ECO_CRATES:
        kind, path = "cargo", _q(name)
    else:
        kind, path = "generic", _q(name)
    return f"pkg:{kind}/{path}" + (f"@{_q(version)}" if version else "")


def build(project: str, sid: str, t: datetime, packages: list[Package]) -> dict:
    """CycloneDX 문서. (이름, 버전, 생태계)가 같은 항목은 한 번만 넣는다(목록 파일은 줄마다 기록하는 기존 규칙 유지)."""
    components: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    used_refs: set[str] = set()
    for p in packages:
        key = (p.name, p.version, p.ecosystem)
        if key in seen:
            continue
        seen.add(key)
        url = purl(p.ecosystem, p.name, p.version if p.pinned else None)
        ref, n = url, 1
        while ref in used_refs:  # bom-ref는 문서 안에서 유일해야 한다(범위 표기가 다른 같은 패키지 등)
            n += 1
            ref = f"{url}#{n}"
        used_refs.add(ref)
        comp: dict = {"type": "library", "bom-ref": ref, "name": p.name}
        if p.pinned:
            comp["version"] = p.version
        comp["purl"] = url
        if not p.pinned:
            comp["properties"] = [{"name": VERSION_SPEC_PROPERTY, "value": p.version}]
        components.append(comp)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(_NAMESPACE, f"{project}/{sid}")),
        "version": 1,
        "metadata": {
            "timestamp": t.astimezone(KST).isoformat(timespec="seconds"),  # +09:00
            "tools": {"components": [{"type": "application", "name": TOOL_NAME}]},
            "component": {"type": "application", "name": project},
        },
        "components": components,
    }


def render(project: str, t: datetime, packages: list[Package]) -> str:
    return json.dumps(build(project, scan_id(t), t, packages), ensure_ascii=False, indent=2) + "\n"
