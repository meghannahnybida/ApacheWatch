FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Expose the web port
EXPOSE 8080

# Run the web server and background monitoring worker.
CMD ["python", "apachewatch.py"]
