FROM python:3.11-slim
WORKDIR /app
COPY ai-security/prompt-injection-defense/ .
RUN pip install fastapi uvicorn
EXPOSE 8000
CMD uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}
