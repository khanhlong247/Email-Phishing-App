FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 25 8000  # Expose both SMTP and API ports

CMD ["sh", "-c", "uvicorn api.ml_api:app --host 0.0.0.0 --port 8000 & python main.py"]