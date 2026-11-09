"""요청 시각. KST(UTC+9) 고정 오프셋으로 직접 계산한다 (4.3 주의 사항)."""
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9), name="KST")


def now_kst() -> datetime:
    return datetime.now(KST)


def scan_id(t: datetime) -> str:
    """파일명과 스캔 ID에 쓰는 YYYYMMDD-HHMMSS (콜론 없음)."""
    return t.astimezone(KST).strftime("%Y%m%d-%H%M%S")


def display_scan_time(sid: str) -> str:
    """스캔 ID(YYYYMMDD-HHMMSS, KST)를 화면용 시각으로."""
    return datetime.strptime(sid, "%Y%m%d-%H%M%S").strftime("%Y-%m-%d %H:%M:%S") + " KST"


def display_time(t: datetime) -> str:
    return t.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S") + " KST"
