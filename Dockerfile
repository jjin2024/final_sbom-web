FROM python:3.13-slim

# API 키는 이미지에 넣지 않는다. 실행할 때 환경 변수로만 전달한다 (예: -e GEMINI_API_KEY).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data

# 일반 사용자로 실행하고, /data는 그 사용자가 쓸 수 있게 만든다.
# 이름 있는 volume을 처음 마운트하면 이 폴더의 소유자가 volume에 그대로 복사된다.
RUN useradd --create-home --uid 10001 app \
    && mkdir /data \
    && chown app:app /data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

USER app
VOLUME /data
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
