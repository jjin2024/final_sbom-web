"""requirements.txt 형식 해석 (R1, R1-3, R1-4).

- 빈 줄과 주석(`#`)은 정상적으로 무시하고 건너뛴 줄 수에 세지 않는다.
- `이름==버전`만 확정 버전이다. 범위 표기는 원문 그대로, 버전 지정이 없으면 `-`로 기록한다.
- 해석할 수 없는 줄(`-r other.txt`, git 주소 등)은 건너뛰고 개수만 센다.
"""
import re
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
