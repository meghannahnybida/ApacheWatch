"""Apache log reading, parsing, and repeated-error grouping."""

import hashlib
import os
import re
from datetime import datetime


def _tail_file(log_path, max_lines):
    """Read the last max_lines lines from a file without loading it into memory.

    Seeks backwards from the end of the file in 8KB chunks, so a 2GB log file
    costs the same as a 10KB one as long as max_lines is small.
    """
    with open(log_path, 'rb') as f:
        f.seek(0, 2)  # Seek to end
        size = f.tell()
        if size == 0:
            return []

        block_size = 8192
        blocks = []
        remaining = size
        newlines_seen = 0

        while remaining > 0 and newlines_seen <= max_lines:
            read_size = min(block_size, remaining)
            remaining -= read_size
            f.seek(remaining)
            block = f.read(read_size)
            blocks.insert(0, block)
            newlines_seen += block.count(b'\n')

        content = b''.join(blocks)
        lines = content.split(b'\n')
        # A trailing newline produces a spurious empty final entry — remove it
        if lines and not lines[-1]:
            lines = lines[:-1]
        return [line.decode('utf-8', errors='replace') for line in lines[-max_lines:]]


def parse_error_log(log_path, max_lines=100, level_filter=None):
    """Parse recent entries from Apache error log.

    Args:
        log_path: Path to the Apache error log file
        max_lines: Maximum number of lines to read from the end of the file
        level_filter: Optional log level to filter by ('error', 'warn', 'info', etc.)
    """
    entries = []

    if not os.path.exists(log_path):
        return entries

    try:
        lines = _tail_file(log_path, max_lines)

        # Pattern for Apache error log
        pattern = r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)'

        for line in lines:
            line = line.strip()
            if not line:
                continue

            match = re.match(pattern, line)
            if match:
                timestamp_str, level_info, message = match.groups()
                # Extract just the level (e.g., "error" from "core:error")
                level = level_info.split(":")[-1] if ":" in level_info else level_info

                entries.append({
                    "timestamp": timestamp_str,
                    "level": level,
                    "message": message[:500]  # Keep enough context for incident grouping
                })
            else:
                # Line didn't match pattern, store as-is
                entries.append({
                    "timestamp": "",
                    "level": "unknown",
                    "message": line[:200]
                })

        # Apply level filter if specified
        if level_filter:
            entries = [e for e in entries if e['level'].lower() == level_filter.lower()]

    except PermissionError:
        entries.append({
            "timestamp": datetime.now().isoformat(),
            "level": "error",
            "message": f"Permission denied reading {log_path}"
        })
    except Exception as e:
        entries.append({
            "timestamp": datetime.now().isoformat(),
            "level": "error",
            "message": f"Error reading log: {str(e)}"
        })

    return entries


def parse_error_timestamp(value):
    """Parse the timestamp formats commonly emitted by Apache error logs."""
    if not value:
        return None
    cleaned = value.strip()
    for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    return None


def extract_affected_urls(message):
    """Extract request paths from common Apache error-message patterns."""
    candidates = []
    patterns = (
        r"\bURL\s+(['\"]?)(/[^\s'\")]+)\1",
        r"\baccess to\s+(/[^\s'\")]+)",
        r"\brequest(?:ed)?(?: URI)?\s+(['\"]?)(/[^\s'\")]+)\1",
        r"\buri\s+(['\"]?)(/[^\s'\")]+)\1",
        r"(/var/www/(?:html|htdocs)/[^\s:'\")]+)",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, message, flags=re.IGNORECASE):
            path = match.group(match.lastindex or 0).rstrip(".,;:")
            if path.startswith("/var/www/html/"):
                path = path[len("/var/www/html"):]
            elif path.startswith("/var/www/htdocs/"):
                path = path[len("/var/www/htdocs"):]
            if path not in candidates:
                candidates.append(path)
    return candidates


def normalize_error_message(message):
    """Remove request-specific values so repeated errors share an incident."""
    normalized = re.sub(r"(?:\s*\[(?:pid|client|remote)\s+[^\]]+\])+\s*", " ", message, flags=re.IGNORECASE)
    normalized = re.sub(r"(\bURL\s+)(['\"]?)/[^\s'\")]+\2", r"\1<url>", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"(\baccess to\s+)/[^\s'\")]+", r"\1<url>", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"(\brequest(?:ed)?(?: URI)?\s+)(['\"]?)/[^\s'\")]+\2", r"\1<url>", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"/var/www/(?:html|htdocs)/[^\s:'\")]+", "<url>", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\bline\s+\d+\b", "line <n>", normalized, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", normalized).strip()


def group_error_incidents(entries, limit=20):
    """Group repeated parsed error-log entries into investigation incidents."""
    groups = {}
    for position, entry in enumerate(entries):
        message = entry.get("message", "")
        level = entry.get("level", "unknown").lower()
        signature = normalize_error_message(message)
        key = (level, signature.lower())
        occurred_at = parse_error_timestamp(entry.get("timestamp", ""))
        incident = groups.setdefault(key, {
            "id": hashlib.sha1(f"{level}:{signature.lower()}".encode()).hexdigest()[:12],
            "level": level, "message": signature, "count": 0,
            "timestamps": [], "affected_urls": [], "occurrences": [],
            "last_position": position,
        })
        incident["count"] += 1
        incident["last_position"] = position
        incident["occurrences"].append({
            "timestamp": entry.get("timestamp", ""),
            "message": message,
            "affected_urls": extract_affected_urls(message),
        })
        # Preserve useful evidence without returning thousands of duplicate rows.
        incident["occurrences"] = incident["occurrences"][-10:]
        if occurred_at:
            incident["timestamps"].append(occurred_at)
        for url in extract_affected_urls(message):
            if url not in incident["affected_urls"]:
                incident["affected_urls"].append(url)

    results = []
    for incident in groups.values():
        timestamps = sorted(incident.pop("timestamps"))
        if timestamps:
            first, last = timestamps[0], timestamps[-1]
            buckets = [0] * 5
            if first == last:
                buckets[-1] = len(timestamps)
            else:
                span = (last - first).total_seconds()
                for timestamp in timestamps:
                    index = min(4, int(((timestamp - first).total_seconds() / span) * 5))
                    buckets[index] += 1
            incident.update(first_seen=first.isoformat(), last_seen=last.isoformat(), trend=buckets)
        else:
            incident.update(first_seen=None, last_seen=None, trend=[incident["count"]])
        incident["occurrences"].reverse()
        incident["occurrences_truncated"] = incident["count"] > len(incident["occurrences"])
        results.append(incident)

    results.sort(key=lambda item: item.pop("last_position"), reverse=True)
    return results[:limit]


def parse_access_log(log_path, max_lines=1000):
    """Parse Apache access log entries.

    Args:
        log_path: Path to the Apache access log file
        max_lines: Maximum number of lines to read from the end of the file

    Returns:
        List of dictionaries containing parsed log entries
    """
    entries = []

    if not os.path.exists(log_path):
        return entries

    try:
        lines = _tail_file(log_path, max_lines)

        # Apache common/combined log format pattern
        # IP - user [timestamp] "method path protocol" status size "referer" "user-agent"
        pattern = r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\S+)\s*"?([^"]*)"?\s*"?([^"]*)"?'

        for line in lines:
            line = line.strip()
            if not line:
                continue

            match = re.match(pattern, line)
            if match:
                ip, user, timestamp, method, path, protocol, status, size, referer, user_agent = match.groups()

                entries.append({
                    "ip": ip,
                    "user": user if user != "-" else None,
                    "timestamp": timestamp,
                    "method": method,
                    "path": path,
                    "protocol": protocol,
                    "status": int(status),
                    "size": int(size) if size.isdigit() else 0,
                    "referer": referer if referer and referer != "-" else None,
                    "user_agent": user_agent if user_agent else None
                })

    except PermissionError:
        print(f"WARNING: Permission denied reading access log: {log_path}", flush=True)
        print("  Try running with sudo, or add your user to the 'adm' group.", flush=True)
    except Exception as e:
        print(f"WARNING: Could not parse access log {log_path}: {e}", flush=True)

    return entries


def parse_access_timestamp(value):
    """Parse an Apache access-log timestamp."""
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    except (TypeError, ValueError):
        return None
