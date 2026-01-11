# ApacheWatch

Simple server monitoring and log analysis for Apache servers.

## What it does

- Shows CPU, memory, and disk usage
- Parses and displays Apache error logs with filtering by severity level
- Analyzes Apache access logs for traffic patterns and statistics
- Provides a web dashboard with real-time metrics
- Stores metrics history in SQLite database
- Generates traffic charts and analytics

## Setup

### Local Installation

```bash
# Install dependencies
pip install flask psutil pyyaml

# Edit config.yaml with your Apache log paths
# Then run:
python apachewatch.py
```

Open `http://localhost:8080` in your browser.

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f
```

See [DOCKER.md](DOCKER.md) for detailed Docker setup instructions.

## Configuration

Edit `config.yaml`:

```yaml
server_name: "my-server"

apache:
  error_log: "/var/log/apache2/error.log"   # Ubuntu/Debian
  access_log: "/var/log/apache2/access.log"
  # error_log: "/var/log/httpd/error_log"   # RHEL/CentOS
  # access_log: "/var/log/httpd/access_log"

database: "./data/apachewatch.db"  # SQLite database for metrics history

web:
  host: "0.0.0.0"  # Use 127.0.0.1 for local-only access
  port: 8080
```

## API Endpoints

- `GET /` - Web dashboard
- `GET /api/metrics` - Current system metrics (JSON)
- `GET /api/logs?level=error` - Recent log entries (JSON, optional level filter)
- `GET /api/history` - Metrics history (JSON)
- `GET /api/access-stats` - Access log analytics (top IPs, pages, status codes)
- `GET /api/traffic-chart?hours=24` - Traffic chart data (JSON, default 24 hours)

## Log Permissions

If you can't read the Apache logs, add your user to the `adm` group:

```bash
sudo usermod -a -G adm $USER
# Then log out and back in
```

## Files

```
ApacheWatch/
├── apachewatch.py      # Main application
├── config.yaml         # Configuration file
├── requirements.txt    # Python dependencies
├── generate_logs.py    # Test log generator
├── Dockerfile          # Docker container config
├── docker-compose.yml  # Docker Compose setup
├── DOCKER.md          # Docker documentation
├── data/              # SQLite database stored here
│   └── apachewatch.db
├── logs/              # Test logs (local development)
├── templates/         # HTML templates
│   └── dashboard.html
└── README.md
```

## Development

### Generate Test Logs

For local testing without Apache:

```bash
python generate_logs.py
```

This creates sample Apache logs in the `./logs/` directory.

## Features

- **Real-time Monitoring**: Live CPU, memory, and disk metrics
- **Log Analysis**: Parse and filter Apache error logs by severity
- **Traffic Analytics**: Analyze access patterns, top pages, and visitor IPs
- **Historical Data**: Track metrics over time with SQLite storage
- **Web Dashboard**: Clean, responsive interface for all metrics
- **Docker Ready**: Full containerization support for easy deployment
