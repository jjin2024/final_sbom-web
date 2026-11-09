"""요약 재사용 (R4-3). "요약됨"이 된 항목의 요약문을 `/data/_cache/summaries.json`에 저장해 두고 다음 요청에서 다시 쓴다.

- 키는 (패키지명, 버전, 취약점 ID)이다. 이 값은 모두 공개 정보라 프로젝트 사이에 공유해도 된다.
- 값은 요약문, 저장 시각, 프롬프트 형식 버전이다. 저장 시각이 TTL보다 오래됐거나 형식 버전이 다르면 쓰지 않는다.
- 파일이 깨졌거나 읽을 수 없으면 캐시가 없는 것으로 본다(요청은 실패하지 않는다).
- 저장은 임시 파일에 쓴 뒤 이름을 바꾸는 방식이다.
- `_cache`는 프로젝트 이름 규칙(영문·숫자로 시작)에 맞지 않아 프로젝트 폴더와 겹치지 않는다.
"""
import json
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path

PROMPT_VERSION = "v1"  # 요약 프롬프트 형식 버전. 프롬프트를 바꾸면 올려서 이전 요약을 쓰지 않게 한다
CACHE_DIRNAME = "_cache"
CACHE_FILENAME = "summaries.json"


def _key(package: str, version: str, vuln_id: str) -> str:
    return json.dumps([package, version, vuln_id], ensure_ascii=False)


class SummaryCache:
    def __init__(self, data_dir: Path, ttl_days: int, now: datetime):
        self._path = data_dir / CACHE_DIRNAME / CACHE_FILENAME
        self._ttl = timedelta(days=ttl_days)
        self._now = now
        self.enabled = ttl_days > 0  # 0이면 읽지도 쓰지도 않는다
        self._entries: dict[str, dict] = self._load() if self.enabled else {}
        self._dirty = False

    def _load(self) -> dict[str, dict]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            entries = data["entries"]
            if not isinstance(entries, dict):
                return {}
            return {k: v for k, v in entries.items() if isinstance(k, str) and isinstance(v, dict)}
        except (OSError, ValueError, KeyError, TypeError):
            return {}  # 없거나, 깨졌거나, 읽을 수 없으면 새로 만든다

    def _fresh(self, entry: dict) -> bool:
        try:
            saved = datetime.fromisoformat(entry["saved_at"])
            return (
                entry["prompt_version"] == PROMPT_VERSION
                and isinstance(entry["summary"], str)
                and bool(entry["summary"])
                and self._now - saved <= self._ttl
            )
        except (KeyError, TypeError, ValueError):
            return False

    def get(self, package: str, version: str, vuln_id: str) -> str | None:
        if not self.enabled:
            return None
        entry = self._entries.get(_key(package, version, vuln_id))
        return entry["summary"] if entry is not None and self._fresh(entry) else None

    def put(self, package: str, version: str, vuln_id: str, summary: str) -> None:
        if not self.enabled:
            return
        self._entries[_key(package, version, vuln_id)] = {
            "summary": summary,
            "saved_at": self._now.isoformat(timespec="seconds"),
            "prompt_version": PROMPT_VERSION,
        }
        self._dirty = True

    def save(self) -> None:
        """새로 넣은 항목이 있을 때만 쓴다. 오래된 항목은 이때 함께 지운다. 실패하면 OSError."""
        if not self.enabled or not self._dirty:
            return
        kept = {k: v for k, v in self._entries.items() if self._fresh(v)}
        folder = self._path.parent
        tmp = folder / f".{CACHE_FILENAME}.{uuid.uuid4().hex}.tmp"
        try:
            folder.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps({"entries": kept}, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise
        self._dirty = False
