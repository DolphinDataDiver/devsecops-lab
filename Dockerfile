FROM python:3.12-slim

# Create non-root user
RUN useradd -m appuser

WORKDIR /app

# Install dependencies first (better caching)
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY api/ .

# Switch to non-root user
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]

