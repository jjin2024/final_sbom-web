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
# 모델 이름은 실제 키로 호출해 확인해야 한다. 환경 변수 GEMINI_MODEL로 바꾼다.
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
DEFAULT_GEMINI_MAX_OUTPUT_TOKENS = 2048


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
            gemini_api_key=(env("GEMINI_API_KEY") or "").strip(),
        )
