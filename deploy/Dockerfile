FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt --no-cache-dir
COPY . .
RUN mkdir -p data
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8080"]
