"""취약점 조회 (R3). OSV를 부르는 부분을 `VulnSource` 뒤로 분리해 테스트에서 바꿔 끼운다 (3.1, 4.1)."""
import http.client
import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Protocol

from . import severity


class LookupFailed(Exception):
    """네트워크 오류, 타임아웃, 응답 오류. 조회를 중단해야 한다는 신호 (R3, R3-3)."""


@dataclass(frozen=True)
class Finding:
    vuln_id: str
    severity: str | None  # 심각/높음/보통/낮음, 모르면 None


class VulnSource(Protocol):
    def query(self, name: str, version: str, ecosystem: str) -> list[Finding]:
        """(이름, 버전, 생태계) 하나에 영향을 주는 취약점. 실패하면 LookupFailed."""
        ...


def query_many(
    source: "VulnSource", targets: list[tuple[str, str, str]], workers: int
) -> list[list[Finding]]:
    """targets의 조회 결과를 targets와 같은 순서로 돌려준다. workers개씩 동시에 조회하지만 결과 순서는
    항상 같다. 하나라도 실패하면(LookupFailed) 아직 시작하지 않은 조회는 취소하고 그 예외를 낸다 (R3-3)."""
    if workers <= 1 or len(targets) <= 1:
        return [source.query(*t) for t in targets]
    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
        futures = [pool.submit(source.query, *t) for t in targets]
        try:
            return [f.result() for f in futures]
        except BaseException:
            for f in futures:
                f.cancel()
            raise


def parse_record(record: dict) -> Finding:
    db_text = (record.get("database_specific") or {}).get("severity")
    level = severity.from_text(db_text)
    if level is None:
        vectors = [s.get("score", "") for s in record.get("severity") or []]
        level = severity.from_vectors(vectors)
    return Finding(vuln_id=record["id"], severity=level)


def record_names(record: dict) -> set[str]:
    """이 기록이 가리키는 모든 이름: 자기 ID와 별칭(CVE, GHSA, PYSEC 등)."""
    return {record["id"], *[a for a in record.get("aliases") or [] if isinstance(a, str)]}


def _best_severity(levels: list[str | None]) -> str | None:
    known = [lv for lv in levels if lv in severity.RANK]
    return min(known, key=severity.RANK.__getitem__) if known else None


def _display_id(names: set[str], record_ids: list[str]) -> str:
    """CVE 별칭이 있으면 CVE, 없으면 GHSA 기록, 그 외는 사전순 첫 ID."""
    cves = sorted(n for n in names if n.startswith("CVE-"))
    if cves:
        return cves[0]
    ghsa = sorted(i for i in record_ids if i.startswith("GHSA-"))
    return ghsa[0] if ghsa else sorted(record_ids)[0]


def merge_aliases(records: list[dict]) -> list[Finding]:
    """같은 취약점이 GHSA와 PYSEC 등 여러 ID로 등록된 기록을 하나로 합친다.
    ID나 별칭이 하나라도 겹치면 같은 취약점으로 본다. 심각도는 가장 높은 것을 쓴다."""
    groups: list[tuple[set[str], list[dict]]] = []
    for rec in records:
        names = record_names(rec)
        hit = [g for g in groups if g[0] & names]
        merged_names, merged_recs = set(names), [rec]
        for g in hit:
            merged_names |= g[0]
            merged_recs = g[1] + merged_recs
            groups.remove(g)
        groups.append((merged_names, merged_recs))
    result = []
    for names, recs in groups:
        ids = [r["id"] for r in recs]
        result.append(Finding(
            vuln_id=_display_id(names, ids),
            severity=_best_severity([parse_record(r).severity for r in recs]),
        ))
    return result


class OsvSource:
    """OSV `/v1/query` 호출. API 키가 필요 없다. 보내는 정보는 이름, 버전, 생태계뿐이다."""

    MAX_PAGES = 20

    def __init__(
        self,
        base_url: str,
        timeout: float,
        opener: Callable[..., object] = urllib.request.urlopen,
    ):
        self._url = base_url.rstrip("/") + "/v1/query"
        self._timeout = timeout
        self._opener = opener

    def query(self, name: str, version: str, ecosystem: str) -> list[Finding]:
        records: dict[str, dict] = {}  # 같은 ID가 페이지에 또 나오면 한 번만
        token: str | None = None
        for _ in range(self.MAX_PAGES):
            body = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
            if token:
                body["page_token"] = token
            data = self._post(body)
            for record in data.get("vulns") or []:
                try:
                    records.setdefault(record["id"], record)
                except (KeyError, TypeError) as e:
                    raise LookupFailed("OSV 응답 형식 오류") from e
            token = data.get("next_page_token")
            if not token:
                try:
                    return merge_aliases(list(records.values()))
                except (KeyError, TypeError, AttributeError) as e:
                    raise LookupFailed("OSV 응답 형식 오류") from e
        raise LookupFailed("OSV 응답 페이지가 너무 많음")

    def _post(self, body: dict) -> dict:
        req = urllib.request.Request(
            self._url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self._opener(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, http.client.HTTPException) as e:
            # 시간 초과, 연결 끊김, 응답이 중간에 잘림(IncompleteRead) 등. 원인(주소, 응답 내용)은 넘기지 않는다
            raise LookupFailed(type(e).__name__) from e
        if not isinstance(data, dict):
            raise LookupFailed("OSV 응답 형식 오류")
        return data
