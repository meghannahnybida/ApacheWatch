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
- `GET /api/resource-history?resource=cpu&hours=24` - CPU, memory, or disk chart points and latest/average/peak readings; ranges: 1, 24, 168, 720 hours, or `all`
- `GET /api/access-stats` - Access log analytics (top IPs, pages, status codes)
- `GET /api/access-logs?limit=100` - Recent parsed access-log requests for interactive inspection
- `GET /api/log-tail?source=error&limit=100` - Original recent error or access log lines in file order (up to 1,000 lines)
- `GET /api/log-search?source=access&q=checkout&ip=192.0.2.10&status=5` - Search the configured log with optional text, IP, URL/path, date, error-level, and response-status filters; returns parsed entries, original lines, and an older-page cursor
- `GET /api/log-stream?source=error&cursor=…` - Read new matching lines from a search's `stream_cursor`, with the same filters
- `GET /api/log-context?source=error&snapshot=…&offset=…` - Read up to three original lines before and after a search result, ignoring filters
- `GET /api/log-views` - List this server's saved log views
- `POST /api/log-views` - Save a named view with `{ "name": "Checkout errors", "state": { ... } }`
- `PATCH /api/log-views/<id>` - Replace a saved view's name and state
- `DELETE /api/log-views/<id>` - Delete a saved view
- `GET /api/block-recommendations` - Advisory IP/range recommendations with evidence and proposed Apache/UFW rules
- `GET /api/action-items?status=open` - Unified alert, recurring-error, and traffic-threat inbox
- `PATCH /api/action-items/<id>` - Save a note, acknowledge, snooze, resolve, dismiss, or reopen a finding
- `GET /api/action-items/<id>/activity?limit=10&before=<event_id>` - Saved activity and note versions, latest first; use `next_before` for earlier events
- `GET /api/traffic-chart?hours=24` - Traffic chart data (JSON, default 24 hours)
- `GET /api/alerts` - Recent local alerts saved in SQLite
- `GET /api/settings/thresholds` - Effective alert thresholds for this server
- `PATCH /api/settings/thresholds` - Save validated threshold overrides
- `GET /api/notifications/email` - Email readiness, recipient, delivery status, and background-check status
- `PATCH /api/notifications/email` - Update email alerts, severity, or recipients independently
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
├── apachewatch.py      # Startup command and WSGI app
├── apachewatch_app/    # Python modules grouped by responsibility
│   ├── application.py  # Flask app factory and UI asset paths
│   ├── configuration.py # Configuration loading and defaults
│   ├── routes.py       # Dashboard and HTTP API
│   ├── cli.py          # Web, worker, and test-email startup
│   ├── monitoring.py   # Background checks
│   ├── metrics.py      # System metrics and source health
│   ├── resource_history.py # Time-filtered resource charts and summaries
│   ├── logs.py         # Log parsing and error grouping
│   ├── log_search.py   # Filtered log search and snapshot pagination
│   ├── log_views.py    # Named, persistent log views
│   ├── traffic.py      # Traffic analytics and security findings
│   ├── alerts.py       # Threshold rules
│   ├── settings.py     # Persistent threshold overrides
│   ├── actions.py      # Action Center findings and workflow
│   ├── activity.py     # Finding activity and saved note versions
│   ├── guidance.py     # Finding explanations and investigation steps
│   ├── database.py     # SQLite schema
│   └── history.py      # Alert, metric, and traffic history
├── notifications.py    # Deferred email delivery feature
├── ip_analyzer.py      # IP and bot identification
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

Start the app with `python apachewatch.py`, or use `apachewatch:app` as the WSGI entry point. Importing the app does not start monitoring. Routes read each app's settings from `app.config["APACHEWATCH"]`; collectors and finding builders receive configuration explicitly. `apachewatch_app.create_app(config_data=...)` creates an isolated app for tests or other deployments.

Run the test suite with `python -m unittest discover -s tests -v`.
Run viewer-command validation with `node --test tests/test_terminal_tools.cjs` (no npm dependencies).

Settings has **General**, **Alerts**, and **Email** tabs. In Alerts, edit the five existing thresholds and choose **Save thresholds**. Changes apply to web requests and background checks without a restart. Email lets you add or remove up to 20 recipients, including while delivery is off. Recipient changes preserve the email on/off setting.

Threshold overrides and email preferences are stored in SQLite and survive restarts; `config.yaml` provides the initial values. Appearance and dashboard refresh remain browser preferences. Saved threshold overrides take precedence over the corresponding values in `config.yaml`.

Each system-resource card has a **Details** link. It opens a spacious view with a prominent latest recorded value, supporting average and peak readings, and a usage status for the selected range: Last hour, Last 24 hours, Last 7 days, Last 30 days, or All available history. There are no resource graphs. **Refresh** reads newly saved samples; opening details does not collect or invent readings.

One sentence reports how many original readings reached the current saved disk alert threshold or the 90% CPU/memory high-usage guide. The guides do not create alerts. This compares recorded readings against the current threshold, rather than counting past alerts or estimating time spent above it. Disabled disk alerts are identified as off. Missing data is shown as unavailable rather than zero usage.

Resource summaries use all valid readings in the selected window, including brief peaks. The read-only `/api/resource-history` endpoint also retains aggregated points for programmatic use, with at most roughly 400 points. Stored server-local or offset-bearing timestamps are normalized to UTC; details display the viewer's local time. The existing raw `/api/history` endpoint remains available.

In Action Center, **Review later** moves a finding out of Needs attention for 15 minutes, 1 hour, 4 hours, or 1 day. The Later queue shows when it will return; **Review now** brings it back sooner. Use **Mark in progress** while investigating and **Mark resolved** after addressing the issue.

Findings open with a short summary, one **Next step**, and an automatically saved note. Expand **Details & guidance** for the impact, remaining checks, and saved evidence. **Review later** expands the scheduling controls. These sections start closed each time a finding is opened. Guidance uses the saved evidence and includes a shortcut to the relevant logs or dashboard view. Findings absent from the latest check are identified separately; a saved log sample may still contain entries from before a fix. Investigation guidance draws on Apache's documentation for [error logs](https://httpd.apache.org/docs/2.4/logs.html), [access rules](https://httpd.apache.org/docs/2.4/howto/access.html), and [upstream services](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html).

Finding notes save automatically as you type and when you close the dialog. The note field shows **Saved** after the server confirms the update. **Retry save** appears only if a save fails. Unsaved drafts are retained in the same browser so you can recover them after a refresh. Saving a note preserves the finding's status and scheduled review time.

Expand **Activity** to load a finding's timeline. It records first detection, saved note changes, workflow decisions, changed review times, returns from Later, and changes in whether a finding is observed. **View saved note** expands a historical note version; clearing the current note preserves the previous version in activity. **Show earlier activity** loads older events, and **Refresh** checks for new events. Saving a note refreshes the timeline while it is expanded; opening a collapsed timeline loads the latest activity.

Activity is stored in SQLite alongside each change, so the timeline and saved state stay consistent across restarts. Unchanged saves and repeated monitoring checks do not add duplicate events. New activity timestamps are stored in UTC and displayed in the browser's local time. Existing findings retain their known first-seen date plus a snapshot marked **Activity tracking started**; changes made before tracking began cannot be reconstructed.

Log Explorer searches the entire currently configured error or access log, including entries older than the initial Lines selection. **Filters** expands date/time, exact client IP (IPv4 or IPv6), and URL/path controls. Text and URL searches are literal and case-insensitive; all selected filters apply together. Error level and HTTP response filters also work in Terminal. Dates use the local times printed in the log, including both endpoints; lines without a readable timestamp are excluded when a date filter is set.

The Level dropdown has five choices: **All levels**, **Errors** (including critical, alert, and emergency), **Warnings**, **Info** (including notice), and **Debug** (including trace 1–8). All levels also includes unrecognized lines. Exact Apache levels remain available through the search API.

Choose **Save current view** to name the current log source, text/IP/path/date filters, severity or HTTP response filter, display format, and line count. **Saved views** reopens a view in one selection, cancels pending reads, and starts a fresh search with live updates paused. Dates are saved exactly as entered, rather than as a moving time range; saved views contain filters, not a copy of the log output.

Changing filters shows that they differ from the selected view and leaves the saved version intact. **Edit view** lets you rename it or update it with the current settings. Its **Delete view** action removes only the saved view and leaves the current filters open. Views are shared on this server, stored in SQLite, and survive browser reloads and app restarts. Names must be unique ignoring case, with up to 80 characters and 50 views per server. Failed saves retain the name draft for retry.

The saved-view API accepts a `name` and a `state` object with `source` (`error` or `access`), `format` (`formatted` or `terminal`), `limit` (10, 20, 50, 100, or 500; Formatted supports up to 100), and the search fields `q`, `ip`, `url`, `from`, `to`, `level`, and `status`. Level uses the viewer's groups (`errors`, `warn`, `information`, `diagnostics`, or empty). Irrelevant source-specific filters must be neutral: error views use `status: "all"`; access views use `level: ""`. Unknown fields, live flags, file paths, and pagination cursors are rejected.

Terminal highlights matching search text, URL text, and client IPs without changing the original log text. Filtered results have a **Context** button that expands up to three original lines before and after that match. Surrounding lines ignore the selected filters and stay within the search's file snapshot, so they may have different dates, IPs, or severity levels.

Terminal colors distinguish timestamps, client addresses, error levels, request methods, and HTTP response statuses. **Wrap lines** remembers its setting in this browser. **Copy output** and **Download** export only the retained original log lines in file order, with a trailing newline; controls and expanded context are excluded. **Fullscreen** opens a focused view with the same controls, its own **Find** field, and continued live updates.

The command input is visible above the output when Terminal opens, with example commands beneath it. The **Commands** button shows or hides it. The separate “Latest … lines” label describes the current view.

With the terminal focused, `/` opens Find, `W` toggles wrapping, `F` toggles fullscreen, `:` opens Commands, and `?` shows shortcuts. With output focused, Space pauses/resumes live collection and Home/End move to the first/latest displayed line. Shortcuts leave typing and browser shortcuts alone. Escape closes search, commands, or a message first, then fullscreen.

**Commands** offers `help`, `tail [error|access] [-n 10|20|50|100|500] [-f]`, `find <literal text>`, and `clear`. For example, `tail access -n 100 -f` resets filters and watches the access log, while `find /checkout` applies text search alongside the current filters. `find ""` clears text search only. `clear` clears displayed output without changing log files, saved search pages, or the live position; Refresh reloads saved lines. These are viewer actions, with no shell execution. Up/Down recall up to 50 commands in the current tab, preserving an unfinished draft; history disappears when the page reloads.

**Watch live** appends new matching lines every five seconds and retains scrollback. Scrolling up stops following output while collection continues; the new-line button returns to the latest output. Pausing and resuming live updates preserves collected output. The browser retains up to 5,000 lines or roughly 2 million characters, whichever comes first; the footer identifies when older output is released. Search remains available for those older entries. Refreshing, changing filters or sources, or browsing pages starts a new view. Rotation or truncation pauses live reading with an explanation and retains the visible output until you refresh.

**Older** and **Newer** navigate matching pages; repeated errors are grouped within each page. Terminal preserves original line text and shows that page in file order. Browsing history pauses live updates, while **Refresh** starts at the latest entries. Pages use a file snapshot so newly appended lines do not shift older pages. A rotated, truncated, or rewritten log prompts a refresh. Search covers the configured file; rotated archives such as `.log.1` and `.gz` are not included.

The search API accepts `source`, `q`, `ip`, `url`, `from`, `to`, `level`, `status` (all, 2, 3, 4, or 5), `limit` (up to 500), and `cursor`. Dates are ISO local date/times without a timezone. Reuse `next_cursor` with the same filters to continue backwards. Each request scans at most roughly 8 MiB, stopping at a line boundary; the dashboard continues across empty batches automatically. `count` is the number of matches on that page, not a total for the file. Search limits individual lines to 1 MiB.

Search also returns `terminal_lines` with byte offsets, a `snapshot` for context lookups, and a `stream_cursor` for forward reads. Streaming returns at most 500 matches per request within the same scan budget; continue immediately when `has_more` is true, including batches with no matches. Keep the same source and filters and use the returned `stream_cursor` for the next read. An unfinished last line is reread at the same offset on the next poll, allowing the viewer to update it without duplication.

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

Email delivery is deferred for now and disabled in this checkout. The implementation and setup outline below are retained for later. The initial recipient is `meghannahnybida@gmail.com`, configured in `config.yaml` under `notifications.email.recipients`. Manage the saved list in **Settings → Email**. The sending service is separate from the recipients.

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
