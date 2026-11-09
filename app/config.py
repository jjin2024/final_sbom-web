"""설정값. 환경 변수로만 읽는다 (4.3). API 키는 여기에 두지 않는다."""
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_UPLOAD_MAX_BYTES = 256 * 1024
DEFAULT_TABLE_MAX_ROWS = 15
DEFAULT_EXTERNAL_TIMEOUT = 10.0
DEFAULT_OSV_URL = "https://api.osv.dev"


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    upload_max_bytes: int = DEFAULT_UPLOAD_MAX_BYTES
    table_max_rows: int = DEFAULT_TABLE_MAX_ROWS
    external_timeout: float = DEFAULT_EXTERNAL_TIMEOUT
    osv_url: str = DEFAULT_OSV_URL

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ.get
        return cls(
            data_dir=Path(env("DATA_DIR", "/data")),
            upload_max_bytes=int(env("UPLOAD_MAX_BYTES", DEFAULT_UPLOAD_MAX_BYTES)),
            table_max_rows=int(env("TABLE_MAX_ROWS", DEFAULT_TABLE_MAX_ROWS)),
            external_timeout=float(env("EXTERNAL_TIMEOUT_SECONDS", DEFAULT_EXTERNAL_TIMEOUT)),
            osv_url=env("OSV_API_URL", DEFAULT_OSV_URL),
        )
