# sbom-web

`requirements.txt` 형식의 파일을 올리면 패키지·버전 목록(SBOM)을 저장하고, [OSV](https://osv.dev)에서 알려진 취약점을 조회해 심각도 순으로 보여 주는 웹 서비스입니다. 인증 없는 단일 사용자 데모이며, 로컬 Docker 실행을 기준으로 합니다.

개발 문서(요구사항, 완료 기준, 설계)는 이 저장소 밖의 `dev-doc-web.md`에 있습니다.

## 진행 상태

| 작업 | 상태 |
|---|---|
| T1 업로드, 목록 저장 | 완료 |
| T2 입력 검증, 해석 규칙 | 완료 |
| T3 OSV 취약점 조회, 표, 보고서 | 완료 |
| T4 Docker 실행, volume 유지 | 완료 |
| T5 화면 한 장 | 일부 완료 (이력 목록, 다운로드 링크, 이전 실행 대비, 요약 집계는 이후) |
| T6 조회 실패 처리 (502) | 미구현 (지금은 OSV 연결 실패 때 500) |
| T7 이력 조회, 재요청, 이전 실행 대비 | 미구현 |
| T8 AI 요약 (Gemini) | 미구현 |
| T9 AI 요약 실패 처리 | 미구현 |

테스트: 91건 통과, 1건 건너뜀(실제 OSV 호출, `OSV_LIVE_TEST=1`). 요구사항, 완료 기준, 변경 기록은 저장소 밖의 개발 문서에 있습니다.

## 실행 (Docker)

```bash
docker build -t sbom-web .
docker run -d --name sbom-web -p 8000:8000 -v sbom-data:/data sbom-web
```

- 브라우저로 http://localhost:8000 에 접속합니다. 기동 확인은 `/healthz`입니다.
- 결과는 volume의 `/data/<프로젝트>/`에 `sbom-<시각>.txt`, `vuln-report-<시각>.txt`로 저장됩니다. `-v`를 빼면 컨테이너를 지울 때 이력도 사라집니다.
- 시각은 한국 시간(KST)으로 고정입니다.
- 인증이 없으므로 외부에 공개하지 마세요.

## API

```bash
curl -F "file=@requirements.txt" http://localhost:8000/api/projects/demo/scans
```

| 메서드 | 경로 | 설명 |
|---|---|---|
| POST | `/api/projects/{project}/scans` | 파일(필드 `file`)을 올려 수집, 저장, 조회 |
| GET | `/healthz` | 기동 확인 |

프로젝트 이름은 영문, 숫자, `.`, `_`, `-`만 쓰고 영문 또는 숫자로 시작하는 1~50자입니다.

## 설정 (환경 변수)

| 이름 | 기본값 | 설명 |
|---|---|---|
| `DATA_DIR` | `/data` | 결과 파일 폴더 |
| `UPLOAD_MAX_BYTES` | `262144` | 업로드 크기 상한 |
| `TABLE_MAX_ROWS` | `15` | 응답용 표의 최대 행 수 |
| `EXTERNAL_TIMEOUT_SECONDS` | `10` | 외부 API 호출 제한 시간 |
| `OSV_API_URL` | `https://api.osv.dev` | OSV 주소 (API 키 불필요) |

API 키는 코드나 이미지에 넣지 않고 환경 변수로만 전달합니다.

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
  parser.py     requirements.txt 해석
  storage.py    결과 파일 저장
  osv.py        OSV 조회 (VulnSource로 분리, 테스트에서 교체)
  severity.py   심각도 등급 변환
  report.py     정렬, 응답용 표, 보고서
  clock.py      KST 시각
  static/       화면 (HTML 한 장)
tests/          확인 사례 기준 테스트
```
