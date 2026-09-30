FROM sagemath/sagemath:latest

# 1. Instalar dependencias del sistema como root
USER root
RUN apt-get update && apt-get install -y libpq-dev gcc && rm -rf /var/lib/apt/lists/*

# 2. Volver al usuario 'sage' para instalar paquetes de Python
USER sage
WORKDIR /app

# 3. Copiar requirements e instalar en el entorno de Sage
COPY requirements.txt .
RUN sage -pip install --no-cache-dir -r requirements.txt

# 4. Copiar el resto del código
COPY . .

EXPOSE 8000

CMD ["sage", "-python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]