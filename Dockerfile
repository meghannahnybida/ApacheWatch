FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Expose the web port
EXPOSE 8080

# Run in development mode with auto-reload
CMD ["python", "apachewatch.py"]
