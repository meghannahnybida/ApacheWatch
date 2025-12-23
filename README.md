# ApacheWatch

Simple server monitoring and log analysis for Apache servers.

## What it does

- Shows CPU, memory, and disk usage
- Displays recent Apache error log entries  
- Provides a simple web dashboard
- Stores metrics history in a JSON file

## Setup

```bash
# Install dependencies (just 3 packages!)
pip install flask psutil pyyaml

# Edit config.yaml with your Apache log paths
# Then run:
python apachewatch.py
```

Open `http://localhost:8080` in your browser.

## Configuration

Edit `config.yaml`:

```yaml
server_name: "my-server"

apache:
  error_log: "/var/log/apache2/error.log"   # Ubuntu/Debian
  # error_log: "/var/log/httpd/error_log"   # RHEL/CentOS

data_file: "./data/apachewatch.json"

web:
  host: "0.0.0.0"
  port: 8080
```

## API Endpoints

- `GET /` - Web dashboard
- `GET /api/metrics` - Current system metrics (JSON)
- `GET /api/logs` - Recent log entries (JSON)
- `GET /api/history` - Metrics history (JSON)

## Log Permissions

If you can't read the Apache logs, add your user to the `adm` group:

```bash
sudo usermod -a -G adm $USER
# Then log out and back in
```

## Files

```
ApacheWatch/
├── apachewatch.py   # The entire application (single file!)
├── config.yaml      # Your configuration
├── data/            # Metrics history stored here
└── README.md
```

That's it! One Python file, one config file.
