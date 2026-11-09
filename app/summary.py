"""AI 요약 (R4). Gemini를 부르는 부분을 `SummarySource` 뒤로 분리해 테스트에서 바꿔 끼운다 (3.1, 4.1).

- 심각도 높은 순으로 최대 N건(기본 50)을 5건씩 묶어 요청한다.
- LLM에 보내는 정보는 패키지명, 버전, 취약점 ID뿐이다. 파일 내용·이름과 프로젝트 이름은 보내지 않는다.
- API 키는 요청 헤더로만 보내고, 주소와 응답, 예외 메시지, 로그에 넣지 않는다.
"""
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from typing import Callable, Protocol

from .report import VulnRow

STATUS_OK = "요약됨"
STATUS_FAILED = "요약 실패"
STATUS_EXCLUDED = "요약 제외(한도 초과)"
STATUS_NO_KEY = "요약 안 함(API 키 없음)"

REASON_NO_VULNS = "요약할 취약점 없음"
REASON_NO_KEY = "API 키 없음"


class SummaryFailed(Exception):
    """정상 완료 응답이 아님(인증 오류, 타임아웃, 응답이 중간에 잘림 등). 원인은 구분하지 않는다 (X5)."""


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
        opener: Callable[..., object] = urllib.request.urlopen,
    ):
        self._key = api_key
        self._url = f"{base_url.rstrip('/')}/v1beta/models/{model}:generateContent"
        self._timeout = timeout
        self._max_tokens = max_output_tokens
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
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            # 원인(주소, 응답 내용)은 호출한 쪽으로 넘기지 않는다
            raise SummaryFailed(type(e).__name__) from e
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

    @property
    def attempted(self) -> bool:
        return self.skipped_reason is None

    @property
    def aggregate(self) -> str:
        return f"요약 {self.succeeded}건 성공, {self.failed}건 실패, {self.excluded}건 제외"

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
        }


def summarize_rows(
    rows: list[VulnRow], source: SummarySource | None, max_items: int, batch_size: int
) -> SummaryOutcome:
    """rows는 심각도 순으로 정렬되어 있어야 한다 (R3-2). 앞에서부터 max_items건을 batch_size건씩 요약한다."""
    if not rows:
        return SummaryOutcome(rows, skipped_reason=REASON_NO_VULNS)
    if source is None:
        return SummaryOutcome(
            [replace(r, summary_status=STATUS_NO_KEY) for r in rows], skipped_reason=REASON_NO_KEY
        )

    targets, rest = rows[:max_items], rows[max_items:]
    done: list[VulnRow] = []
    for start in range(0, len(targets), batch_size):
        batch = targets[start:start + batch_size]
        texts = source.summarize([SummaryItem(r.package, r.version, r.vuln_id) for r in batch])
        done += [replace(r, summary_status=STATUS_OK, summary=t) for r, t in zip(batch, texts)]
    excluded = [replace(r, summary_status=STATUS_EXCLUDED) for r in rest]
    return SummaryOutcome(done + excluded, succeeded=len(done), excluded=len(excluded))
