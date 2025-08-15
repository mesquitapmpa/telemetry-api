FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copia o código
COPY app ./app
COPY main.py .        # seu main está na raiz
# COPY .env .         # (opcional) só se quiser a .env dentro da imagem

EXPOSE 8000 5010
CMD ["uvicorn","main:app","--host","0.0.0.0","--port","8000","--proxy-headers","--forwarded-allow-ips","*"]