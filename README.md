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
pip install -r requirements.txt

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

alerts:
  enabled: true
  cooldown_minutes: 30
  thresholds:
    disk_percent: 85
    server_errors_5xx: 5
    client_errors_4xx: 50
    requests_per_ip: 100
    bot_percentage: 75

security:
  minimum_score: 35
  allowlist:                 # Never recommend these IPs/networks for blocking
    - 127.0.0.0/8
    - ::1/128

web:
  host: "0.0.0.0"  # Use 127.0.0.1 for local-only access
  port: 8080
```

## API Endpoints

- `GET /` - Web dashboard
- `GET /api/metrics` - Current system metrics (JSON)
- `GET /api/monitoring-health` - Apache process visibility and configured log-source health
- `GET /api/logs?level=error` - Recent log entries (JSON, optional level filter)
- `GET /api/incidents?level=error&limit=20` - Repeated errors grouped into incidents with timestamps, affected URLs, and trend data
- `GET /api/history` - Metrics history (JSON)
- `GET /api/access-stats` - Access log analytics (top IPs, pages, status codes)
- `GET /api/access-logs?limit=100` - Recent parsed access-log requests for interactive inspection
- `GET /api/log-tail?source=error&limit=100` - Original recent error or access log lines in file order (up to 1,000 lines)
- `GET /api/block-recommendations` - Advisory IP/range recommendations with evidence and proposed Apache/UFW rules
- `GET /api/action-items?status=open` - Unified alert, recurring-error, and traffic-threat inbox
- `PATCH /api/action-items/<id>` - Acknowledge, snooze, resolve, dismiss, or reopen a finding
- `GET /api/traffic-chart?hours=24` - Traffic chart data (JSON, default 24 hours)
- `GET /api/alerts` - Recent local alerts saved in SQLite
- `GET /api/notifications/email` - Email readiness, recipient, delivery status, and background-check status
- `PATCH /api/notifications/email` - Enable/disable email alerts and select critical-only or critical-and-warning findings
- `POST /api/notifications/email/test` - Queue a test to the configured recipients (JSON body `{}`; limited to one per minute)

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

### Test Alerts Locally

The background worker evaluates findings every minute, even when the dashboard is closed. Dashboard/API requests can also refresh local alerts. To verify alerting with test logs, temporarily lower thresholds in `config.yaml`, for example:

```yaml
alerts:
  thresholds:
    requests_per_ip: 2
    client_errors_4xx: 1
```

Check Action Center or open `http://localhost:8080/api/alerts`.

### Email Notifications

Email delivery is deferred for now and disabled in this checkout. The implementation and setup outline below are retained for later. The intended recipient is `meghannahnybida@gmail.com`, configured in `config.yaml` under `notifications.email.recipients`. The sending service is separate from the recipient.

1. Copy `.env.example` to `.env` and fill in your outgoing email service's SMTP host, port, username, password, and sending address. Use `starttls` for a STARTTLS connection or `ssl` for implicit TLS, with the port supplied by your service. `.env` is ignored by Git and loaded by the app; existing deployment environment variables take precedence.
2. Set `APACHEWATCH_PUBLIC_URL` if recipients should get a link to your deployed dashboard.
3. Install requirements and restart ApacheWatch. For Docker, rebuild and recreate the service with `docker compose up -d --build --force-recreate`.
4. Open **Settings → Email notifications**, enable alerts, and choose **Send test email** after the sender is connected and background checks are running. The UI distinguishes a queued test from a successfully sent test.

Critical findings are emailed by default. Settings can also include warnings or turn email off; these preferences are stored for this server. Repeated emails use the alert cooldown (30 minutes by default, with a five-minute minimum for email). Snoozed, dismissed, resolved, and no-longer-observed findings do not generate email. Failed deliveries use a durable queue with up to five attempts and increasing delays. Delivery status means the SMTP service accepted the message; inbox placement depends on the email service.

`python apachewatch.py` starts both the web server and monitoring worker. The worker records metrics, refreshes traffic history and Action Center, and sends queued email without requiring an open browser. Development reloading is available with `python apachewatch.py --debug`; the reload parent does not run a second worker.

For a WSGI deployment that imports the Flask app, run one separate monitoring process alongside it:

```bash
python apachewatch.py --monitor-only
```

A command-line delivery check is also available:

```bash
python apachewatch.py --test-email
```

Keep the web service and monitoring process on the same configuration, database, and sending-service environment. No email is queued or sent until delivery is configured.

## Features

- **Real-time Monitoring**: Live CPU, memory, and disk metrics
- **Log Analysis**: Parse and filter Apache error logs by severity
- **Terminal View**: View original error or access log lines, with live polling every five seconds and optional automatic scrolling
- **Traffic Analytics**: Analyze access patterns, top pages, and visitor IPs
- **IP Visitor Analysis**: Identify bots vs real users via reverse DNS hostname lookup
  - Detects search engine bots (Googlebot, Bingbot, etc.)
  - Shows hostname for each visitor IP
  - Tracks bot vs human traffic percentages
- **Historical Data**: Track metrics over time with SQLite storage
- **Local Alerts**: Save threshold-based alerts to SQLite and expose them through the dashboard/API
- **Email Notifications**: Background finding checks, severity preferences, durable retries, and delivery status in Settings
- **Action Center**: Track alerts, recurring errors, and traffic threats through acknowledgement, snooze, resolution, and dismissal
- **Web Dashboard**: Clean, responsive interface for all metrics
- **Docker Ready**: Full containerization support for easy deployment
