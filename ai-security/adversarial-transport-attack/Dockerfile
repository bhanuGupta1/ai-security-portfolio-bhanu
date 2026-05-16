FROM python:3.11-slim

WORKDIR /code

# Install CPU-only torch first (smaller, faster build)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Install API deps
RUN pip install --no-cache-dir fastapi uvicorn

# Copy project
COPY . .

# HF Spaces runs on port 7860
EXPOSE 7860

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860"]
