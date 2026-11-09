"""설정값. 환경 변수로만 읽는다 (4.3). API 키는 코드, 이미지, 로그에 넣지 않는다."""
import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_UPLOAD_MAX_BYTES = 256 * 1024
DEFAULT_TABLE_MAX_ROWS = 15
DEFAULT_EXTERNAL_TIMEOUT = 10.0
DEFAULT_OSV_URL = "https://api.osv.dev"
DEFAULT_SUMMARY_MAX_ITEMS = 50
DEFAULT_SUMMARY_BATCH_SIZE = 5
DEFAULT_GEMINI_URL = "https://generativelanguage.googleapis.com"
# 모델 이름은 시간이 지나면 종료된다(gemini-2.5-flash는 신규 사용자에게 404). 환경 변수 GEMINI_MODEL로 바꾼다.
# gemini-3.5-flash는 2026-11-09에 실제 호출로 확인했다(HTTP 200, finishReason STOP, 약 3.7초).
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash"
DEFAULT_GEMINI_MAX_OUTPUT_TOKENS = 2048
DEFAULT_GEMINI_TIMEOUT = 60.0  # LLM 응답은 OSV보다 느려서 외부 호출 제한 시간(10초)과 따로 둔다
# 생각(thinking) 수준. 비우면 설정을 보내지 않는다(지원하지 않는 모델용).
DEFAULT_GEMINI_THINKING_LEVEL = "low"


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    upload_max_bytes: int = DEFAULT_UPLOAD_MAX_BYTES
    table_max_rows: int = DEFAULT_TABLE_MAX_ROWS
    external_timeout: float = DEFAULT_EXTERNAL_TIMEOUT
    osv_url: str = DEFAULT_OSV_URL
    summary_max_items: int = DEFAULT_SUMMARY_MAX_ITEMS
    summary_batch_size: int = DEFAULT_SUMMARY_BATCH_SIZE
    gemini_url: str = DEFAULT_GEMINI_URL
    gemini_model: str = DEFAULT_GEMINI_MODEL
    gemini_max_output_tokens: int = DEFAULT_GEMINI_MAX_OUTPUT_TOKENS
    gemini_timeout: float = DEFAULT_GEMINI_TIMEOUT
    gemini_thinking_level: str = DEFAULT_GEMINI_THINKING_LEVEL
    # repr=False: 설정을 출력하거나 로그에 남겨도 키가 보이지 않게 한다
    gemini_api_key: str = field(default="", repr=False)

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ.get
        return cls(
            data_dir=Path(env("DATA_DIR", "/data")),
            upload_max_bytes=int(env("UPLOAD_MAX_BYTES", DEFAULT_UPLOAD_MAX_BYTES)),
            table_max_rows=int(env("TABLE_MAX_ROWS", DEFAULT_TABLE_MAX_ROWS)),
            external_timeout=float(env("EXTERNAL_TIMEOUT_SECONDS", DEFAULT_EXTERNAL_TIMEOUT)),
            osv_url=env("OSV_API_URL", DEFAULT_OSV_URL),
            summary_max_items=int(env("SUMMARY_MAX_ITEMS", DEFAULT_SUMMARY_MAX_ITEMS)),
            summary_batch_size=int(env("SUMMARY_BATCH_SIZE", DEFAULT_SUMMARY_BATCH_SIZE)),
            gemini_url=env("GEMINI_API_URL", DEFAULT_GEMINI_URL),
            gemini_model=env("GEMINI_MODEL", DEFAULT_GEMINI_MODEL),
            gemini_max_output_tokens=int(
                env("GEMINI_MAX_OUTPUT_TOKENS", DEFAULT_GEMINI_MAX_OUTPUT_TOKENS)
            ),
            gemini_timeout=float(env("GEMINI_TIMEOUT_SECONDS", DEFAULT_GEMINI_TIMEOUT)),
            gemini_thinking_level=env("GEMINI_THINKING_LEVEL", DEFAULT_GEMINI_THINKING_LEVEL).strip(),
            gemini_api_key=(env("GEMINI_API_KEY") or "").strip(),
        )
