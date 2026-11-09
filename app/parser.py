"""의존성 파일 해석 (R1, R1-3, R1-4, R1-5).

지원하는 파일: requirements.txt 형식(기본), package-lock.json, package.json, go.mod, Cargo.lock.
파일 이름이 위 이름이면 그 형식으로, 아니면 requirements.txt 형식으로 해석한다(`parse_upload`).

[requirements.txt 형식]

- 빈 줄과 주석(`#`)은 정상적으로 무시하고 건너뛴 줄 수에 세지 않는다.
- `이름==버전`만 확정 버전이다. 범위 표기는 원문 그대로, 버전 지정이 없으면 `-`로 기록한다.
- 해석할 수 없는 줄(`-r other.txt`, git 주소 등)은 건너뛰고 개수만 센다.
"""
import json
import re
import tomllib
from dataclasses import dataclass

ECO_PYPI = "PyPI"
ECO_NPM = "npm"
ECO_GO = "Go"
ECO_CRATES = "crates.io"
ECOSYSTEM = ECO_PYPI  # requirements.txt 형식의 생태계(기존 이름 유지)

_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$")
_SPEC = re.compile(r"^(===|==|~=|!=|<=|>=|<|>)\s*[A-Za-z0-9.*+!_-]+$")
_PIN = re.compile(r"^==[A-Za-z0-9.+!_-]+$")  # 와일드카드(*)와 쉼표가 없어야 확정


@dataclass(frozen=True)
class Package:
    name: str
    version: str  # 확정 버전, 범위 표기 원문, 또는 "-"
    ecosystem: str = ECOSYSTEM
    pinned: bool = True  # 확정 버전(==)이면 True


@dataclass(frozen=True)
class ParseResult:
    packages: list[Package]
    skipped_lines: int

    @property
    def not_looked_up(self) -> int:
        return sum(1 for p in self.packages if not p.pinned)


def _strip_comment(line: str) -> str:
    # 줄 끝 주석(" # ...")과 환경 마커(" ; ...")는 버린다
    line = re.split(r"\s#", line, maxsplit=1)[0]
    return line.split(";", 1)[0].strip()


def _parse_line(line: str) -> Package | None:
    m = _LINE.match(line)
    if not m:
        return None
    name, rest = m.group(1), m.group(2).replace(" ", "")
    if rest == "":
        return Package(name, "-", pinned=False)
    specs = rest.split(",")
    if not all(_SPEC.match(s) for s in specs):
        return None
    if len(specs) == 1 and _PIN.match(specs[0]):
        return Package(name, specs[0][2:], pinned=True)
    return Package(name, rest, pinned=False)


def parse_requirements(text: str) -> ParseResult:
    packages: list[Package] = []
    skipped = 0
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        pkg = _parse_line(_strip_comment(stripped))
        if pkg is None:
            skipped += 1
        else:
            packages.append(pkg)
    return ParseResult(packages, skipped)


# ---------------------------------------------------------------------------------------------
# 다른 언어의 의존성 파일 (R1-5). 표준 라이브러리(json, tomllib)만 쓴다.
# ---------------------------------------------------------------------------------------------

class FormatError(Exception):
    """파일 이름은 지원하는 이름인데 내용이 그 형식이 아니다. API는 400으로 응답한다."""


_EXACT_SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
_NODE_MODULES = "node_modules/"


def _load_json(text: str, filename: str):
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        raise FormatError(f"형식을 해석할 수 없음: {filename}은(는) 올바른 JSON이어야 합니다") from None
    if not isinstance(data, dict):
        raise FormatError(f"형식을 해석할 수 없음: {filename}의 최상위는 객체여야 합니다")
    return data


def parse_package_lock(text: str) -> ParseResult:
    """package-lock.json (lockfileVersion 2, 3의 `packages`). 모든 항목이 확정 버전이다.

    건너뛰는 항목: 루트(`""`, 프로젝트 자신이라 건너뛴 수에 세지 않음), `link: true`, 버전이 없는 항목,
    `node_modules/` 아래가 아닌 항목(작업 공간 폴더 등). 앞의 둘을 뺀 나머지는 건너뛴 수에 센다.
    """
    data = _load_json(text, "package-lock.json")
    entries = data.get("packages")
    if not isinstance(entries, dict):  # lockfileVersion 1은 `packages`가 없고 `dependencies`만 있다
        raise FormatError(
            "지원하지 않는 lockfile 버전: lockfileVersion 2 또는 3의 package-lock.json만 지원합니다"
        )
    packages: list[Package] = []
    skipped = 0
    for key, info in entries.items():
        if key == "":
            continue
        if not isinstance(info, dict) or info.get("link") is True:
            skipped += 1
            continue
        version = info.get("version")
        at = key.rfind(_NODE_MODULES)
        name = key[at + len(_NODE_MODULES):] if at >= 0 else ""
        if not isinstance(version, str) or not version or not name:
            skipped += 1
            continue
        packages.append(Package(name, version, ECO_NPM))
    return ParseResult(packages, skipped)


def parse_package_json(text: str) -> ParseResult:
    """package.json의 `dependencies`와 `devDependencies`. 정확한 버전(x.y.z, 프리릴리스·빌드 접미사 허용)만
    확정이고, 그 외(`^`, `~`, `>=`, `*`, `latest`, URL 등)는 원문(공백 제거)을 `(확정 버전 아님)`으로 기록한다."""
    data = _load_json(text, "package.json")
    packages: list[Package] = []
    skipped = 0
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section)
        if deps is None:
            continue
        if not isinstance(deps, dict):
            raise FormatError(f"형식을 해석할 수 없음: package.json의 {section}는 객체여야 합니다")
        for name, spec in deps.items():
            if not isinstance(spec, str):
                skipped += 1
                continue
            spec = spec.strip()
            if _EXACT_SEMVER.match(spec):
                packages.append(Package(name, spec, ECO_NPM))
            else:
                packages.append(Package(name, re.sub(r"\s+", "", spec) or "-", ECO_NPM, pinned=False))
    return ParseResult(packages, skipped)


_GO_IGNORED_DIRECTIVES = {"module", "go", "toolchain", "godebug", "replace", "exclude", "retract", "tool", "ignore"}


def _go_requirement(text: str) -> Package | None:
    parts = text.split()
    if len(parts) != 2:
        return None
    return Package(parts[0], parts[1], ECO_GO)  # 버전은 `v` 접두사까지 원문 그대로


def parse_go_mod(text: str) -> ParseResult:
    """go.mod의 `require` 한 줄과 `require ( ... )` 블록. `// indirect` 같은 주석은 버린다.
    `module`, `go`, `toolchain`, `replace`, `exclude`, `retract` 줄(블록 안의 줄 포함)은 해석 대상이 아니므로
    건너뛴 줄 수에 센다. 빈 줄과 주석만 있는 줄은 세지 않는다."""
    packages: list[Package] = []
    skipped = 0
    block = ""  # "" | "require" | "other"
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if block:
            if line == ")":
                block = ""
            elif block == "require":
                pkg = _go_requirement(line)
                if pkg:
                    packages.append(pkg)
                else:
                    skipped += 1
            else:
                skipped += 1
            continue
        parts = line.split(None, 1)  # 공백과 탭 모두 구분자
        head = parts[0]
        rest = parts[1].strip() if len(parts) > 1 else ""
        if head == "require":
            if rest == "(":
                block = "require"
            else:
                pkg = _go_requirement(rest)
                if pkg:
                    packages.append(pkg)
                else:
                    skipped += 1
        else:
            skipped += 1
            if head in _GO_IGNORED_DIRECTIVES and rest == "(":
                block = "other"
    return ParseResult(packages, skipped)


def _is_crates_io(source: str) -> bool:
    return source.startswith(("registry+", "sparse+")) and "crates.io" in source


def parse_cargo_lock(text: str) -> ParseResult:
    """Cargo.lock의 `[[package]]`(`name`, `version`). crates.io 레지스트리에서 온 항목만 읽는다.
    `source`가 없는 항목(프로젝트 자신, 경로 의존성)과 git 등 다른 출처는 건너뛰고 건너뛴 수에 센다."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        raise FormatError("형식을 해석할 수 없음: Cargo.lock은 올바른 TOML이어야 합니다") from None
    entries = data.get("package", [])
    if not isinstance(entries, list):
        raise FormatError("형식을 해석할 수 없음: Cargo.lock의 package는 표의 목록이어야 합니다")
    packages: list[Package] = []
    skipped = 0
    for item in entries:
        name = item.get("name") if isinstance(item, dict) else None
        version = item.get("version") if isinstance(item, dict) else None
        source = item.get("source") if isinstance(item, dict) else None
        if not (isinstance(name, str) and isinstance(version, str) and isinstance(source, str)
                and _is_crates_io(source)):
            skipped += 1
            continue
        packages.append(Package(name, version, ECO_CRATES))
    return ParseResult(packages, skipped)


_BY_FILENAME = {
    "package-lock.json": parse_package_lock,
    "package.json": parse_package_json,
    "go.mod": parse_go_mod,
    "Cargo.lock": parse_cargo_lock,
}
SUPPORTED_FILENAMES = ("requirements.txt", *_BY_FILENAME)


def parse_upload(filename: str | None, text: str) -> ParseResult:
    """업로드한 파일 이름으로 종류를 정한다. 지원하는 이름이 아니면 requirements.txt 형식으로 해석한다
    (`my-deps.txt` 같은 이름도 그대로 동작). 이름의 경로 부분은 무시한다."""
    base = (filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    return _BY_FILENAME.get(base, parse_requirements)(text)
