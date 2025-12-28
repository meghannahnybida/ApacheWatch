# ApacheWatch - Docker Development Guide

## Development Mode (with auto-reload)

Your code is mounted into the container, so **any changes you make are instantly reflected** - no rebuild needed!

### Quick Start

```bash
# Start the container
docker compose up

# Or run in background
docker compose up -d
```

Visit `http://localhost:8080`

### How it works

The `docker-compose.yml` mounts your entire project directory into the container:
```yaml
volumes:
  - .:/app  # Your code → live updates!
```

Flask's debug mode (enabled by default) auto-reloads when you edit Python files.

### Making changes

1. Edit `apachewatch.py` or `templates/dashboard.html` on your local machine
2. Save the file
3. Refresh your browser - changes are live!

**No need to rebuild or restart the container.**

### Logs Setup

**For macOS/Windows (no local Apache):**
```bash
# Create dummy log files for testing
mkdir -p logs
touch logs/error.log logs/access.log
```

The `docker-compose.yml` is already set up to use `./logs` directory.

**For Linux with Apache installed:**
Edit `docker-compose.yml` and change:
```yaml
- ./logs:/logs:ro
```
to:
```yaml
- /var/log/apache2:/logs:ro
```

### Docker Commands

```bash
# Start
docker compose up

# Stop (Ctrl+C or)
docker compose down

# View logs
docker compose logs -f

# Rebuild (only needed if you change requirements.txt)
docker compose build

# Run commands inside container
docker compose exec apachewatch python -c "import psutil; print(psutil.cpu_percent())"
```

### File Structure

```
ApacheWatch/
├── apachewatch.py        # Your Python code (auto-reloads)
├── templates/
│   └── dashboard.html    # Your HTML (edit anytime)
├── config.yaml           # Configuration
├── logs/                 # Mounted log directory
├── data/                 # Persisted metrics history
├── Dockerfile           # Container definition
└── docker-compose.yml   # Development setup
```

### Deploying to a Remote Server

When ready, copy this to your server:

```bash
# On remote server
docker compose up -d

# Update docker-compose.yml to mount real Apache logs:
# - /var/log/apache2:/logs:ro
```

The same container works for both development and production!
