FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copie cada coisa para um destino claro
COPY app/ ./app/
COPY main.py ./main.py

EXPOSE 8000 5010
CMD ["uvicorn","main:app","--host","0.0.0.0","--port","8000","--proxy-headers","--forwarded-allow-ips","*"]