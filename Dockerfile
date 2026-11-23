FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy metadata and package sources before editable installation so setuptools discovers all packages
COPY pyproject.toml README.md ./
COPY src ./src
COPY data ./data
COPY eval ./eval
COPY config ./config
COPY scripts ./scripts

# Install Python dependencies (including Chainlit UI + dev checks)
RUN pip install --no-cache-dir -e ".[ui,dev]"

# Create non-root user
RUN useradd -m -u 1000 auditguard && chown -R auditguard:auditguard /app
USER auditguard

EXPOSE 8000 8001 8010 8011 8012 8013

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
