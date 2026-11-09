"""AI 요약 (R4). Gemini를 부르는 부분을 `SummarySource` 뒤로 분리해 테스트에서 바꿔 끼운다 (3.1, 4.1).

- 심각도 높은 순으로 최대 N건(기본 50)을 5건씩 묶어 요청한다.
- LLM에 보내는 정보는 패키지명, 버전, 취약점 ID뿐이다. 파일 내용·이름과 프로젝트 이름은 보내지 않는다.
- API 키는 요청 헤더로만 보내고, 주소와 응답, 예외 메시지, 로그에 넣지 않는다.
"""
import http.client
import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from typing import Callable, Protocol

from .report import VulnRow
from .summary_cache import SummaryCache

log = logging.getLogger("sbom.summary")

STATUS_OK = "요약됨"
STATUS_REUSED = "요약됨(재사용)"
STATUS_FAILED = "요약 실패"
STATUS_EXCLUDED = "요약 제외(한도 초과)"
STATUS_NO_KEY = "요약 안 함(API 키 없음)"

REASON_NO_VULNS = "요약할 취약점 없음"
REASON_NO_KEY = "API 키 없음"


# 이 HTTP 상태로 실패하면 남은 묶음도 같은 이유로 실패하므로 더 요청하지 않는다(사용 한도 초과, 인증·권한 오류)
FATAL_HTTP_CODES = frozenset({401, 403, 429})


class SummaryFailed(Exception):
    """정상 완료 응답이 아님(인증 오류, 타임아웃, 응답이 중간에 잘림 등). 원인은 응답에 구분해 넣지 않는다 (X5).
    fatal이면(HTTP 429, 401, 403) 남은 묶음을 요청하지 않는다 (R4-2)."""

    def __init__(self, message: str = "", fatal: bool = False):
        super().__init__(message)
        self.fatal = fatal


@dataclass(frozen=True)
class SummaryItem:
    """LLM에 보내는 정보의 전부."""
    package: str
    version: str
    vuln_id: str


class SummarySource(Protocol):
    def summarize(self, items: list[SummaryItem]) -> list[str]:
        """항목마다 설명과 업그레이드 권장 한 덩어리를 같은 순서로 돌려준다. 실패하면 SummaryFailed."""
        ...


_PROMPT = (
    "다음은 알려진 취약점이 있는 소프트웨어 패키지 목록입니다. 항목마다 "
    "(1) 이 취약점이 무엇인지 한두 문장으로 설명하고 "
    "(2) 업그레이드 등 권장 조치를 한 문장으로 쓰세요. "
    "확실하지 않은 내용은 추측하지 말고 '확인 필요'라고 쓰세요. "
    "각 항목의 id를 그대로 돌려주세요.\n\n입력:\n"
)

_SCHEMA = {
    "type": "ARRAY",
    "items": {
        "type": "OBJECT",
        "properties": {
            "id": {"type": "INTEGER"},
            "description": {"type": "STRING"},
            "upgrade": {"type": "STRING"},
        },
        "required": ["id", "description", "upgrade"],
    },
}


class GeminiSource:
    """Gemini REST 호출(`generateContent`). 정상 완료는 HTTP 성공 + finishReason이 STOP + 모든 항목의 요약이 있음."""

    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        timeout: float,
        max_output_tokens: int,
        thinking_level: str = "",
        opener: Callable[..., object] = urllib.request.urlopen,
    ):
        # thinking_level이 비어 있으면 thinkingConfig를 보내지 않는다(지원하지 않는 모델용)
        self._key = api_key
        model = model.strip().removeprefix("models/")  # 모델 목록의 이름(models/...)을 그대로 써도 된다
        self._url = f"{base_url.rstrip('/')}/v1beta/models/{model}:generateContent"
        self._timeout = timeout
        self._max_tokens = max_output_tokens
        self._thinking = thinking_level.strip()
        self._opener = opener

    def summarize(self, items: list[SummaryItem]) -> list[str]:
        payload = [
            {"id": i, "package": it.package, "version": it.version, "vulnerability": it.vuln_id}
            for i, it in enumerate(items, start=1)
        ]
        body = {
            "contents": [
                {"role": "user", "parts": [{"text": _PROMPT + json.dumps(payload, ensure_ascii=False)}]}
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": self._max_tokens,
                "responseMimeType": "application/json",
                "responseSchema": _SCHEMA,
            },
        }
        if self._thinking:
            # 요약에는 깊은 추론이 필요 없다. 생각 토큰은 응답 시간과 maxOutputTokens 한도를 쓴다
            # (실제 호출: 생각 1,400여 토큰, 약 10초 -> 줄이면 2~4초)
            body["generationConfig"]["thinkingConfig"] = {"thinkingLevel": self._thinking}
        data = self._post(body)
        try:
            candidate = data["candidates"][0]
            if candidate.get("finishReason") != "STOP":
                raise SummaryFailed("not completed")  # 토큰 한도, 안전 차단 등은 구분하지 않는다
            text = "".join(p.get("text", "") for p in candidate["content"]["parts"])
            results = json.loads(text)
            by_id = {int(r["id"]): r for r in results}
            if set(by_id) != set(range(1, len(items) + 1)):
                raise SummaryFailed("items mismatch")
            return [f"{by_id[i]['description'].strip()} 권장: {by_id[i]['upgrade'].strip()}"
                    for i in range(1, len(items) + 1)]
        except SummaryFailed:
            raise
        except (KeyError, IndexError, TypeError, ValueError, AttributeError) as e:
            raise SummaryFailed("bad response") from e

    def _post(self, body: dict) -> dict:
        req = urllib.request.Request(
            self._url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "x-goog-api-key": self._key},
            method="POST",
        )
        try:
            with self._opener(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # 진단용으로 상태 코드(숫자)만 남긴다. 주소, 헤더(키), 응답 본문은 넣지 않는다
            raise SummaryFailed(f"HTTP {e.code}", fatal=e.code in FATAL_HTTP_CODES) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, http.client.HTTPException) as e:
            # 시간 초과, 연결 끊김, 응답이 중간에 잘림(IncompleteRead) 등. 원인(주소, 응답 내용)은 넘기지 않는다
            raise SummaryFailed(type(e).__name__) from None
        if not isinstance(data, dict):
            raise SummaryFailed("bad response")
        return data


@dataclass
class SummaryOutcome:
    rows: list[VulnRow]
    succeeded: int = 0
    failed: int = 0
    excluded: int = 0
    skipped_reason: str | None = None  # 요약 단계를 건너뛴 이유 (키 없음, 취약점 없음)
    calls: int = 0  # 이 요청에서 Gemini를 부른 횟수
    reused: int = 0  # 캐시의 요약을 다시 쓴 건수(성공 건수에 포함)

    @property
    def attempted(self) -> bool:
        return self.skipped_reason is None

    @property
    def aggregate(self) -> str:
        return f"요약 {self.succeeded}건 성공, {self.failed}건 실패, {self.excluded}건 제외"

    @property
    def usage_line(self) -> str:
        return f"요약 호출 {self.calls}회, 재사용 {self.reused}건"

    @property
    def report_text(self) -> str:
        """보고서의 `## 요약 집계` 구역 내용. 건너뛴 경우에는 안내만 넣는다."""
        return f"{self.aggregate}\n{self.usage_line}" if self.attempted else self.skip_message

    @property
    def skip_message(self) -> str:
        if self.skipped_reason == REASON_NO_KEY:
            return "요약 건너뜀(API 키 없음)"
        return "요약 단계 생략(요약할 취약점 없음)"

    def to_json(self) -> dict:
        if not self.attempted:
            return {"skipped_reason": self.skipped_reason, "message": self.skip_message}
        return {
            "succeeded": self.succeeded,
            "failed": self.failed,
            "excluded": self.excluded,
            "text": self.aggregate,
            "calls": self.calls,
            "reused": self.reused,
        }


def summarize_rows(
    rows: list[VulnRow],
    source: SummarySource | None,
    max_items: int,
    batch_size: int,
    cache: SummaryCache | None = None,
) -> SummaryOutcome:
    """rows는 심각도 순으로 정렬되어 있어야 한다 (R3-2). 앞에서부터 max_items건이 요약 대상이다(캐시와 무관).
    대상 중 캐시에 있는 항목은 호출 없이 채우고(R4-3), 나머지를 batch_size건씩 묶어 요청한다."""
    if not rows:
        return SummaryOutcome(rows, skipped_reason=REASON_NO_VULNS)
    if source is None:
        return SummaryOutcome(
            [replace(r, summary_status=STATUS_NO_KEY) for r in rows], skipped_reason=REASON_NO_KEY
        )

    targets, rest = rows[:max_items], rows[max_items:]
    result: dict[int, VulnRow] = {}  # 대상 안에서의 위치 -> 결과 행
    misses: list[int] = []
    reused = 0
    for pos, r in enumerate(targets):
        text = cache.get(r.package, r.version, r.vuln_id) if cache else None
        if text is None:
            misses.append(pos)
        else:
            result[pos] = replace(r, summary_status=STATUS_REUSED, summary=text)
            reused += 1

    calls = failed = 0
    succeeded = reused
    for start in range(0, len(misses), batch_size):
        batch_pos = misses[start:start + batch_size]
        batch = [targets[p] for p in batch_pos]
        # 묶음마다 성공과 실패를 따로 판정한다 (R4-2). 일반 실패는 해당 묶음만 실패로 표시하고 계속한다.
        calls += 1
        try:
            texts = source.summarize([SummaryItem(r.package, r.version, r.vuln_id) for r in batch])
            if len(texts) != len(batch):
                raise SummaryFailed("items mismatch")
        except SummaryFailed as e:
            # 원인은 서버 로그에만 남긴다(키, 주소, 응답 내용은 없는 짧은 메시지). 응답과 화면에는 넣지 않는다
            log.warning("요약 묶음 실패 (%d건): %s", len(batch), e)
            for p, r in zip(batch_pos, batch):
                result[p] = replace(r, summary_status=STATUS_FAILED)
            failed += len(batch)
            if e.fatal:
                # 사용 한도 초과나 인증 오류는 남은 묶음도 같은 이유로 실패하므로 요청하지 않는다
                remaining = misses[start + batch_size:]
                log.warning("요약 중단: 남은 %d건은 요청하지 않음 (%s)", len(remaining), e)
                for p in remaining:
                    result[p] = replace(targets[p], summary_status=STATUS_FAILED)
                failed += len(remaining)
                break
            continue
        for p, r, t in zip(batch_pos, batch, texts):
            result[p] = replace(r, summary_status=STATUS_OK, summary=t)
            if cache:
                cache.put(r.package, r.version, r.vuln_id, t)
        succeeded += len(batch)
    excluded = [replace(r, summary_status=STATUS_EXCLUDED) for r in rest]
    done = [result[p] for p in range(len(targets))]
    return SummaryOutcome(
        done + excluded, succeeded=succeeded, failed=failed, excluded=len(excluded),
        calls=calls, reused=reused,
    )
