FROM sagemath/sagemath:latest

USER sage
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN sage -pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8010

CMD ["sage", "-python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8010"]
