"""T12: OSV 병렬 조회와 업로드 크기 상한 기본값(1MB). 결과 순서와 호출 기록은 순서대로 조회할 때와 같아야 한다."""
import json
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.config import DEFAULT_LOOKUP_WORKERS, DEFAULT_UPLOAD_MAX_BYTES, Settings
from app.main import create_app, lookup_targets
from app.osv import Finding, LookupFailed, query_many
from app.parser import parse_requirements

from .fakes import FakeSource

KST = timezone(timedelta(hours=9))


class SlowSource:
    """조회마다 지연을 두는 가짜 OSV. 앞쪽 항목일수록 오래 걸려 완료 순서가 요청 순서와 뒤집힌다."""

    def __init__(self, n, base=0.02, fail_at=None):
        self.n, self.base, self.fail_at = n, base, fail_at
        self.calls = []
        self.started = 0
        self.lock = threading.Lock()
        self.max_concurrent = 0
        self.current = 0

    def query(self, name, version, ecosystem):
        i = int(name.removeprefix("p"))
        with self.lock:
            self.calls.append((name, version, ecosystem))
            self.current += 1
            self.max_concurrent = max(self.max_concurrent, self.current)
        try:
            time.sleep(self.base * (self.n - i) / self.n + 0.005)
            if self.fail_at is not None and i == self.fail_at:
                raise LookupFailed("blocked")
            return [Finding(f"V-{i:03d}-{k}", "높음") for k in range(i % 3)]
        finally:
            with self.lock:
                self.current -= 1


def targets(n):
    return [(f"p{i}", "1.0.0", "npm") for i in range(n)]


def test_results_keep_the_requested_order_even_when_completion_order_differs():
    n = 24
    src = SlowSource(n)
    got = query_many(src, targets(n), 8)
    sequential = query_many(SlowSource(n, base=0), targets(n), 1)
    assert got == sequential  # 완료 순서가 뒤집혀도 요청 순서대로 모은다
    assert len(src.calls) == n and sorted(src.calls) == sorted(targets(n))  # 호출 기록도 같은 항목, 같은 횟수


def test_it_really_runs_in_parallel_but_not_beyond_the_worker_count():
    n = 16
    src = SlowSource(n, base=0.2)
    start = time.time()
    query_many(src, targets(n), 8)
    elapsed = time.time() - start
    sequential_estimate = sum(0.2 * (n - i) / n + 0.005 for i in range(n))  # 약 1.8초
    assert elapsed < sequential_estimate * 0.6
    assert 2 <= src.max_concurrent <= 8  # 동시에 8개를 넘지 않는다


@pytest.mark.parametrize("workers", [1, 0, -3])
def test_one_or_fewer_workers_runs_sequentially(workers):
    src = SlowSource(6, base=0)
    query_many(src, targets(6), workers)
    assert src.max_concurrent == 1 and src.calls == targets(6)  # 순서대로, 하나씩


def test_single_or_no_target_needs_no_pool():
    assert query_many(SlowSource(1, base=0), targets(1), 8) == [[]]
    assert query_many(SlowSource(0, base=0), [], 8) == []


def test_a_failure_raises_lookup_failed_and_cancels_the_rest():
    n = 60
    src = SlowSource(n, base=0.05, fail_at=0)
    with pytest.raises(LookupFailed):
        query_many(src, targets(n), 2)
    assert len(src.calls) < n  # 아직 시작하지 않은 조회는 취소된다


def test_failure_in_the_middle_still_fails_the_whole_request():
    src = SlowSource(10, base=0, fail_at=7)
    with pytest.raises(LookupFailed):
        query_many(src, targets(10), 4)


def test_fake_source_records_every_call_even_from_threads():
    src = FakeSource({("a", "1", "npm"): [Finding("X-1", "높음")]})
    query_many(src, [("a", "1", "npm")] + [(f"b{i}", "1", "npm") for i in range(40)], 8)
    assert len(src.calls) == 41 and ("a", "1", "npm") in src.calls


# ---- 앱 전체: 병렬이든 아니든 결과가 같다 ----

def _run(tmp_path, workers, requirements):
    d = tmp_path / f"w{workers}"
    fixed = datetime(2026, 11, 9, 10, 0, 0, tzinfo=KST)
    src = FakeSource({
        (f"pkg{i}", "1.0.0"): [Finding(f"TEST-{i:03d}-{k}", ["낮음", "높음", "심각", "보통"][(i + k) % 4])
                               for k in range(i % 4)]
        for i in range(60)
    })
    c = TestClient(create_app(Settings(data_dir=d, lookup_workers=workers), vuln_source=src, clock=lambda: fixed))
    r = c.post("/api/projects/demo/scans", files={"file": ("requirements.txt", requirements)})
    folder = d / "demo"
    files = {p.name: p.read_bytes() for p in sorted(folder.iterdir())}
    return r.json(), files, src


def test_app_results_files_and_call_records_do_not_depend_on_the_worker_count(tmp_path):
    requirements = "".join(f"pkg{i}==1.0.0\n" for i in range(60)).encode()
    seq_body, seq_files, seq_src = _run(tmp_path, 1, requirements)
    par_body, par_files, par_src = _run(tmp_path, 8, requirements)
    assert seq_body == par_body  # 표, 건수, 비교, 요약 안내까지 같은 응답
    assert seq_files == par_files  # 목록, CycloneDX, 보고서 파일이 바이트까지 같다
    assert sorted(seq_src.calls) == sorted(par_src.calls) and len(par_src.calls) == 60


def test_app_failure_with_parallel_lookup_keeps_the_502_behavior(tmp_path):
    fixed = datetime(2026, 11, 9, 10, 0, 0, tzinfo=KST)
    src = FakeSource({}, fail_for={("pkg30", "1.0.0")})
    c = TestClient(create_app(Settings(data_dir=tmp_path / "d", lookup_workers=8), vuln_source=src, clock=lambda: fixed))
    r = c.post("/api/projects/demo/scans",
               files={"file": ("requirements.txt", "".join(f"pkg{i}==1.0.0\n" for i in range(60)).encode())})
    assert r.status_code == 502 and "조회 실패, 목록은 저장됨" in r.json()["error"]
    names = sorted(p.name for p in (tmp_path / "d" / "demo").iterdir())
    assert names == ["sbom-20261109-100000.cdx.json", "sbom-20261109-100000.txt"]  # 새 보고서는 없다
    assert "secret-host" not in r.text


# ---- 설정 ----

def test_defaults_and_environment_overrides(monkeypatch, tmp_path):
    assert DEFAULT_LOOKUP_WORKERS == 8 and DEFAULT_UPLOAD_MAX_BYTES == 1024 * 1024
    assert Settings(data_dir=tmp_path).lookup_workers == 8
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.delenv("LOOKUP_WORKERS", raising=False)
    monkeypatch.delenv("UPLOAD_MAX_BYTES", raising=False)
    s = Settings.from_env()
    assert s.lookup_workers == 8 and s.upload_max_bytes == 1048576
    monkeypatch.setenv("LOOKUP_WORKERS", "3")
    monkeypatch.setenv("UPLOAD_MAX_BYTES", "2048")
    s = Settings.from_env()
    assert s.lookup_workers == 3 and s.upload_max_bytes == 2048


def test_default_upload_limit_accepts_a_lockfile_sized_file_and_rejects_over_1mb(client):
    lock = {"lockfileVersion": 3, "packages": {"": {"name": "x"}}}
    for i in range(3000):  # 약 300KB: 이전 기본값(256KB)이면 413이던 크기
        lock["packages"][f"node_modules/some-package-name-{i}"] = {
            "version": "1.0.0", "resolved": f"https://registry.npmjs.org/some-package-name-{i}/-/x-1.0.0.tgz",
            "integrity": "sha512-" + "A" * 80}
    raw = json.dumps(lock).encode()
    assert 256 * 1024 < len(raw) < 1024 * 1024
    r = client.post("/api/projects/demo/scans", files={"file": ("package-lock.json", raw)})
    assert r.status_code == 201 and r.json()["collected"] == 3000
    too_big = client.post("/api/projects/big/scans", files={"file": ("requirements.txt", b"#" * (1024 * 1024 + 1))})
    assert too_big.status_code == 413 and "1048576" in too_big.json()["error"]


def test_lookup_targets_dedup_is_unchanged():
    pk = parse_requirements("a==1\na==1\nb==2\nc>=3\n").packages
    assert lookup_targets(pk) == [("a", "1", "PyPI"), ("b", "2", "PyPI")]
