# sbom-web

의존성 파일(`requirements.txt`, `package-lock.json`, `package.json`, `go.mod`, `Cargo.lock`)을 올리면 패키지·버전 목록(SBOM)을 저장하고 표준 형식 CycloneDX JSON으로도 만들며, [OSV](https://osv.dev)에서 알려진 취약점을 조회해 심각도 순으로 보여 주는 웹 서비스입니다. 인증 없는 단일 사용자 데모이며, 로컬 Docker 실행을 기준으로 합니다.

개발 문서(요구사항, 완료 기준, 설계, 변경 기록)는 이 저장소의 [`docs/dev-doc.md`](docs/dev-doc.md)에 있습니다. 상세 규칙, 확인 사례 전체, 변경 기록 전문은 [`docs/appendix.md`](docs/appendix.md)에 있습니다.

## 구현 상태

- 요구사항을 모두 구현했고 완료 기준 82개 사례를 확인했습니다. 자동 시험은 396건 통과, 7건 건너뜀입니다(실제 OSV 5건 `OSV_LIVE_TEST=1`, 실제 Gemini 2건 `GEMINI_LIVE_TEST=1`은 환경 변수가 있을 때만 실행).
- 남은 문제: 50건 규모(Gemini 10회 호출)의 전체 응답 시간은 확인하지 못했고, 한 번에 파일 하나만 올릴 수 있습니다. 자세한 내용은 개발 문서 5.4에 있습니다.
- 실제 OSV와 Gemini로 캡처한 화면은 [`docs/screenshots/`](docs/screenshots/)에 있습니다.

## 시연 실행

무료 Gemini 키는 모델당 하루 20회 요청 한도가 있어서(아래 참고), 점검마다 요약 호출 수를 줄이는 것이 안전합니다. 시연할 때는 요약할 건수를 5건으로 줄여서 실행하세요 (기본값은 50건이고 5건씩 묶어 요청하므로 5건이면 점검 1번에 호출 1회, 하루에 약 20번 시연할 수 있음). **시연 전에 실제 호출 시험이나 연습을 많이 하면 한도가 바닥나니 주의하세요.**

```powershell
$env:GEMINI_API_KEY = "발급받은키"   # 현재 터미널에서만 유효
docker run -d --name sbom-web -p 8000:8000 -v sbom-data:/data -e GEMINI_API_KEY -e SUMMARY_MAX_ITEMS=5 sbom-web
```

시연 순서: ① 파일을 올려 결과 표와 요약 확인 ② 파일을 조금 고쳐 다시 올려 "이전 실행 대비" 확인 ③ 컨테이너를 지웠다가 같은 volume으로 다시 띄워도 이력(`LOAD HISTORY`)이 남아 있는 것 확인.

## 실행 (Docker)

```bash
docker build -t sbom-web .
docker run -d --name sbom-web -p 8000:8000 -v sbom-data:/data sbom-web
```

- 브라우저로 http://localhost:8000 에 접속합니다. 기동 확인은 `/healthz`입니다.
- 결과는 volume의 `/data/<프로젝트>/`에 `sbom-<시각>.txt`, `sbom-<시각>.cdx.json`(CycloneDX 1.5), `vuln-report-<시각>.txt`로 저장됩니다. `-v`를 빼면 컨테이너를 지울 때 이력도 사라집니다.
- 시각은 한국 시간(KST)으로 고정입니다.
- 인증이 없으므로 외부에 공개하지 마세요.

## 사용 방법

1. `project_name`에 프로젝트 이름을 입력하고 `package_file`에서 의존성 파일을 선택한 뒤 `RUN VULNERABILITY SCAN`을 누릅니다. 파일 이름이 `package-lock.json`, `package.json`, `go.mod`, `Cargo.lock`이면 그 형식으로, 아니면 `requirements.txt` 형식으로 읽습니다.
2. 결과에서 수집 건수, 이전 실행 대비, 취약점 표(심각도 순 15행), 요약 집계를 확인하고 링크(sbom, report, cyclonedx)로 파일을 내려받습니다.
3. 같은 프로젝트 이름으로 파일을 바꿔 다시 올리면(1초 이상 간격) 이전 실행 대비가 나옵니다. `LOAD HISTORY`로 과거 점검을 봅니다.

문제가 생기면: 포트 8000이 사용 중이면 `-p 8001:8000`으로 실행하고, 컨테이너 이름이 겹치면 `docker rm -f sbom-web` 후 다시 실행합니다. 요약이 "요약 실패"이면 `docker logs sbom-web`를 봅니다(`HTTP 429`는 하루 한도 초과). "요약 안 함(API 키 없음)"은 키 없이 실행한 것입니다.

## API

```bash
curl -F "file=@requirements.txt" http://localhost:8000/api/projects/demo/scans
```

파일 이름으로 형식을 정합니다: `package-lock.json`, `package.json`(npm), `go.mod`(Go), `Cargo.lock`(crates.io). 그 외 이름은 `requirements.txt`(PyPI) 형식으로 읽습니다. 선언 파일은 직접 의존성만, 잠금 파일은 전이 의존성까지 담습니다.

| 메서드 | 경로 | 설명 |
|---|---|---|
| POST | `/api/projects/{project}/scans` | 파일(필드 `file`)을 올려 수집, 저장, 조회. 201, 이전 실행 대비(`comparison`)와 내려받기 경로(`links`) 포함. 같은 초에 같은 프로젝트로 다시 요청하면 409, 조회 실패는 502 |
| GET | `/api/projects/{project}/scans` | 프로젝트의 이력(최신순). 이력이 없으면 빈 목록 |
| GET | `/api/projects/{project}/scans/{scan_id}/sbom` | 목록 파일 내려받기 (없으면 404) |
| GET | `/api/projects/{project}/scans/{scan_id}/report` | 보고서 내려받기 (조회 실패한 스캔은 없어서 404) |
| GET | `/api/projects/{project}/scans/{scan_id}/cyclonedx` | CycloneDX JSON 내려받기 (파일이 없는 과거 스캔은 404) |
| GET | `/healthz` | 기동 확인 |

프로젝트 이름은 영문, 숫자, `.`, `_`, `-`만 쓰고 영문 또는 숫자로 시작하는 1~50자입니다.

## 설정 (환경 변수)

| 이름 | 기본값 | 설명 |
|---|---|---|
| `DATA_DIR` | `/data` | 결과 파일 폴더 |
| `UPLOAD_MAX_BYTES` | `1048576` | 업로드 크기 상한 |
| `LOOKUP_WORKERS` | `8` | OSV 동시 조회 수 (잠금 파일 460개 기준 순서대로 218초, 8개 동시 27초) |
| `TABLE_MAX_ROWS` | `15` | 응답용 표의 최대 행 수 |
| `EXTERNAL_TIMEOUT_SECONDS` | `10` | 외부 API 호출 제한 시간 |
| `OSV_API_URL` | `https://api.osv.dev` | OSV 주소 (API 키 불필요) |
| `GEMINI_API_KEY` | (없음) | Gemini API 키. 없으면 서버는 정상 기동하고 요약만 건너뜀 |
| `GEMINI_MODEL` | `gemini-3.5-flash` | 요약에 쓸 모델. 모델은 시간이 지나면 종료되므로 404가 나오면 아래 목록 명령으로 확인 |
| `GEMINI_TIMEOUT_SECONDS` | `60` | Gemini 호출 제한 시간 (OSV의 `EXTERNAL_TIMEOUT_SECONDS`와 따로) |
| `GEMINI_THINKING_LEVEL` | `low` | 모델의 생각 수준. 낮을수록 빠르다. 이 설정을 지원하지 않는 모델이면 빈 값으로 끔 |
| `GEMINI_API_URL` | `https://generativelanguage.googleapis.com` | Gemini 주소 |
| `GEMINI_MAX_OUTPUT_TOKENS` | `2048` | 요약 요청의 최대 출력 토큰 |
| `SUMMARY_MAX_ITEMS` | `50` | 요약할 최대 취약점 수 (심각도 높은 순) |
| `SUMMARY_BATCH_SIZE` | `5` | 한 번에 요약 요청하는 항목 수 |
| `SUMMARY_CACHE_TTL_DAYS` | `30` | 요약 재사용 기간(일). `/data/_cache/summaries.json`에 저장한 요약을 이 기간 안에는 다시 쓴다(프로젝트 사이 공유). 0이면 캐시를 쓰지 않음 |

요약이 "요약 실패"로 나오면 서버 로그에서 원인을 확인하세요 (`docker logs sbom-web`, 예: `요약 묶음 실패 (5건): HTTP 429`는 사용 한도 초과). **무료 키는 모델 하나당 하루 20회 요청**만 허용합니다. 요약 호출 1번이 1회를 쓰므로 `SUMMARY_MAX_ITEMS=10`이면 점검 1번에 2회, 기본 50건이면 10회를 씁니다. 한도가 차면(HTTP 429, 인증 오류 401·403 포함) 남은 묶음은 요청하지 않고 요약만 실패하며 표, 이전 실행 대비, 이력, 링크는 정상입니다. 한 번 성공한 요약은 저장해 두었다가 같은 취약점이 나오면 호출 없이 "요약됨(재사용)"으로 채우므로 같은 파일을 다시 점검해도 호출이 줄어듭니다(결과 화면에 `요약 호출 N회, 재사용 N건`). 한도는 모델마다 따로라서 `-e GEMINI_MODEL=gemini-3.1-flash-lite`처럼 모델을 바꿔 피할 수 있습니다. 한도를 확인하려면 호출 1번으로 오류 메시지를 보면 됩니다 (`limit: 20 ... retry in ...`).

## API 키 넣는 법

API 키는 코드, 이미지, 로그에 넣지 않고 환경 변수로만 전달합니다. 채팅이나 저장소에 붙여넣지 마세요.

```powershell
# 현재 터미널에서만 (PowerShell)
$env:GEMINI_API_KEY = "발급받은키"
# 값 없이 -e 이름만 쓰면 현재 터미널의 값을 컨테이너로 전달합니다 (명령어 기록에 키가 남지 않음)
docker run -d --name sbom-web -p 8000:8000 -v sbom-data:/data -e GEMINI_API_KEY sbom-web
```

- 파일로 관리하려면 저장소 밖에 `gemini.env`(`GEMINI_API_KEY=발급받은키` 한 줄)를 두고 `--env-file gemini.env`로 전달하세요. `.env` 파일은 `.gitignore`와 `.dockerignore`에 들어 있습니다.
- 실제 Gemini 호출 확인: 키를 설정한 터미널에서 `$env:GEMINI_LIVE_TEST = "1"; .venv\Scripts\python -m pytest -q tests/test_t8.py -k real_gemini`
- 사용 가능한 모델 목록: `curl.exe -H "x-goog-api-key: $env:GEMINI_API_KEY" https://generativelanguage.googleapis.com/v1beta/models`

## 개발

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt   # macOS/Linux: .venv/bin/python
.venv/Scripts/python -m pytest -q
.venv/Scripts/python -m uvicorn app.main:app --port 8000      # DATA_DIR을 지정하세요
```

- 테스트는 OSV를 가짜 응답으로 바꿔 끼워 실행하므로 네트워크가 필요 없습니다. 실제 OSV를 한 번 부르는 시험은 `OSV_LIVE_TEST=1`일 때만 실행됩니다.

## 구조

```
app/
  main.py       API와 요청 흐름
  parser.py     파일 이름별 해석 (requirements.txt, package-lock.json, package.json, go.mod, Cargo.lock)
  cyclonedx.py  CycloneDX 1.5 JSON 만들기
  compare.py    이전 실행 대비 (PyPI 이름은 PEP 503 정규화)
  summary.py    Gemini 요약 (SummarySource로 분리, 묶음별 실패, 429·401·403 중단)
  summary_cache.py  요약 재사용 저장소 (/data/_cache/summaries.json)
  storage.py    결과 파일 저장
  osv.py        OSV 조회 (VulnSource로 분리, 테스트에서 교체)
  severity.py   심각도 등급 변환
  report.py     정렬, 응답용 표, 보고서
  clock.py      KST 시각
  static/       화면 (HTML 한 장)
tests/          확인 사례 기준 테스트
```
