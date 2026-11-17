# Базовый образ можно заменить на зеркало: --build-arg PYTHON_IMAGE=<зеркало>/python:3.12-slim
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY axisec ./axisec
COPY policies ./policies

RUN useradd --system --uid 10001 axisec && mkdir /data && chown axisec /data
USER axisec
ENV AXISEC_AUDIT_DB=/data/audit.sqlite
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health').status == 200 else 1)"
CMD ["python", "-m", "axisec", "--host", "0.0.0.0", "--port", "8080"]
