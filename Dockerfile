FROM python:3.11-slim

# Herramientas esenciales para monitorización y depuración
RUN apt-get update && apt-get install -y --no-install-recommends \
    procps curl fping openssh-client nmap arp-scan && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY templates ./templates
RUN mkdir -p /app/data

# Crear usuario con UID 1000 para que SSH no se queje
RUN groupadd -g 1000 sherlockes && \
    useradd -u 1000 -g 1000 -m -d /home/sherlockes sherlockes && \
    chown -R sherlockes:sherlockes /app

EXPOSE 8080

CMD ["python3", "main.py"]
