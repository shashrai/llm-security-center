FROM python:3.11-slim

WORKDIR /app

# System deps for spaCy and aiosqlite
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spaCy NLP model
RUN python -m spacy download en_core_web_sm

COPY . .

# Create data directory for audit vault
RUN mkdir -p /data

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
