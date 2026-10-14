"""Access-log statistics and advisory security findings."""

import concurrent.futures
import ipaddress
import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from .configuration import DEFAULT_SECURITY_CONFIG
from .logs import parse_access_timestamp

try:
    from ip_analyzer import analyze_ip_visitor
    IP_ANALYSIS_AVAILABLE = True
except ImportError:
    IP_ANALYSIS_AVAILABLE = False
    print("Warning: IP analysis module not available")


SUSPICIOUS_PATH_PATTERNS = (
    (re.compile(r"/(?:\.env|\.git(?:/|$)|\.svn(?:/|$))", re.I), "sensitive-file probing"),
    (re.compile(r"/(?:wp-admin|wp-login\.php|xmlrpc\.php)(?:/|$|\?)", re.I), "WordPress probing"),
    (re.compile(r"/(?:phpmyadmin|pma|adminer)(?:/|$|\?)", re.I), "database-admin probing"),
    (re.compile(r"/(?:cgi-bin|vendor/phpunit|actuator|server-status)(?:/|$|\?)", re.I), "server or exploit probing"),
    (re.compile(r"(?:\.\./|%2e%2e|%00|/etc/passwd|/proc/self)", re.I), "path-traversal probing"),
)


def _network_for_ip(address):
    prefix = 24 if address.version == 4 else 64
    return ipaddress.ip_network(f"{address}/{prefix}", strict=False)


def _is_allowlisted(address, allowlist):
    for value in allowlist:
        try:
            if address in ipaddress.ip_network(value, strict=False):
                return True
        except ValueError:
            continue
    return False


def analyze_block_recommendations(entries, security_config=None):
    """Score suspicious client IPs and ranges without taking blocking action."""
    security_config = security_config or DEFAULT_SECURITY_CONFIG
    allowlist = security_config.get("allowlist", [])
    minimum_score = max(0, min(100, int(security_config.get("minimum_score", 35))))
    by_ip = defaultdict(list)
    for entry in entries:
        by_ip[entry.get("ip", "")].append(entry)

    recommendations = []
    for ip, ip_entries in by_ip.items():
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if address.is_loopback or _is_allowlisted(address, allowlist):
            continue

        total = len(ip_entries)
        statuses = Counter(entry.get("status") for entry in ip_entries)
        client_errors = sum(count for status, count in statuses.items() if status and 400 <= status < 500)
        auth_failures = sum(count for status, count in statuses.items() if status in (401, 403))
        not_found = statuses.get(404, 0)
        suspicious_paths = []
        suspicious_behaviors = set()
        for entry in ip_entries:
            path = entry.get("path", "")
            for pattern, label in SUSPICIOUS_PATH_PATTERNS:
                if pattern.search(path):
                    suspicious_behaviors.add(label)
                    if path not in suspicious_paths and len(suspicious_paths) < 8:
                        suspicious_paths.append(path)

        minute_counts = Counter()
        parsed_times = []
        for entry in ip_entries:
            timestamp = parse_access_timestamp(entry.get("timestamp"))
            if timestamp:
                parsed_times.append(timestamp)
                minute_counts[timestamp.replace(second=0, microsecond=0)] += 1
        peak_per_minute = max(minute_counts.values(), default=0)

        user_agents = {entry.get("user_agent") or "" for entry in ip_entries}
        scanner_agent = any(
            not agent or re.search(r"(?:curl|wget|python-requests|nikto|sqlmap|nmap|masscan)", agent, re.I)
            for agent in user_agents
        )

        score = 0
        reasons = []
        if suspicious_paths:
            points = min(45, 25 + (len(suspicious_paths) - 1) * 5)
            score += points
            reasons.append(f"{len(suspicious_paths)} suspicious path{'s' if len(suspicious_paths) != 1 else ''} requested")
        if total >= 100:
            score += 20
            reasons.append(f"high request volume ({total} requests)")
        elif total >= 40:
            score += 10
            reasons.append(f"elevated request volume ({total} requests)")
        if total >= 5 and not_found / total >= 0.7:
            score += 25
            reasons.append(f"{round(not_found / total * 100)}% of requests returned 404")
        if auth_failures >= 10:
            score += 25
            reasons.append(f"{auth_failures} authorization failures")
        elif auth_failures >= 5:
            score += 15
            reasons.append(f"{auth_failures} authorization failures")
        if peak_per_minute >= 30:
            score += 25
            reasons.append(f"burst of {peak_per_minute} requests/minute")
        elif peak_per_minute >= 10:
            score += 15
            reasons.append(f"burst of {peak_per_minute} requests/minute")
        if scanner_agent and (suspicious_paths or client_errors >= 5):
            score += 10
            reasons.append("scanner-like or missing user agent")

        score = min(score, 100)
        if score < minimum_score:
            continue
        action = "block_ip" if score >= 60 else "watch"
        recommendations.append({
            "target": ip,
            "target_type": "ip",
            "action": action,
            "score": score,
            "confidence": "high" if score >= 75 else "medium" if score >= 50 else "low",
            "reasons": reasons,
            "requests": total,
            "client_errors": client_errors,
            "error_rate": round(client_errors / total * 100, 1),
            "peak_requests_per_minute": peak_per_minute,
            "suspicious_paths": suspicious_paths,
            "behaviors": sorted(suspicious_behaviors),
            "first_seen": min(parsed_times).isoformat() if parsed_times else None,
            "last_seen": max(parsed_times).isoformat() if parsed_times else None,
            "rules": {
                "apache": f"Require not ip {ip}",
                "ufw": f"sudo ufw deny from {ip}",
            },
        })

    # Recommend a range only when multiple independently suspicious IPs cluster in it.
    range_members = defaultdict(list)
    for item in recommendations:
        if item["score"] >= 50:
            address = ipaddress.ip_address(item["target"])
            range_members[str(_network_for_ip(address))].append(item)
    for network, members in range_members.items():
        if len(members) < 2:
            continue
        score = min(100, round(sum(item["score"] for item in members) / len(members)) + 10)
        recommendations.append({
            "target": network,
            "target_type": "range",
            "action": "consider_range",
            "score": score,
            "confidence": "high" if len(members) >= 4 and score >= 75 else "medium",
            "reasons": [f"{len(members)} suspicious IPs share this network"],
            "member_ips": [item["target"] for item in members],
            "requests": sum(item["requests"] for item in members),
            "client_errors": sum(item["client_errors"] for item in members),
            "suspicious_paths": list(dict.fromkeys(path for item in members for path in item["suspicious_paths"]))[:8],
            "rules": {
                "apache": f"Require not ip {network}",
                "ufw": f"sudo ufw deny from {network}",
            },
        })

    action_order = {"block_ip": 0, "consider_range": 1, "watch": 2}
    recommendations.sort(key=lambda item: (action_order[item["action"]], -item["score"], item["target"]))
    return recommendations


def analyze_access_logs(entries):
    """Analyze access log entries to generate statistics.

    Args:
        entries: List of parsed access log entries

    Returns:
        Dictionary containing analytics data
    """
    if not entries:
        return {
            "top_ips": [],
            "top_pages": [],
            "status_codes": {},
            "total_requests": 0,
            "unique_visitors": 0,
            "bot_stats": {
                "total_bots": 0,
                "total_humans": 0,
                "bot_percentage": 0
            }
        }

    # Count IPs
    ip_counter = Counter(entry["ip"] for entry in entries)

    # Enhanced IP analysis with hostname and bot detection
    enriched_ips = []
    bot_count = 0
    human_count = 0

    if IP_ANALYSIS_AVAILABLE:
        # Pre-collect one user agent per unique IP to avoid scanning entries repeatedly
        ip_user_agents = {}
        for entry in entries:
            ip = entry["ip"]
            if ip not in ip_user_agents and entry.get("user_agent"):
                ip_user_agents[ip] = entry["user_agent"]

        top_ip_list = ip_counter.most_common(20)

        def _analyze_ip(ip_count):
            ip, count = ip_count
            result = analyze_ip_visitor(ip, ip_user_agents.get(ip))
            result["requests"] = count
            return result

        # Run all DNS lookups in parallel (max 4 seconds total) instead of
        # sequentially (up to 2s × 20 IPs = 40s worst case)
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_map = {executor.submit(_analyze_ip, pair): pair[0] for pair in top_ip_list}
            try:
                for future in as_completed(future_map, timeout=4):
                    try:
                        enriched_ips.append(future.result())
                    except Exception:
                        pass
            except concurrent.futures.TimeoutError:
                # Collect whatever finished within the time limit
                for future in future_map:
                    if future.done():
                        try:
                            enriched_ips.append(future.result())
                        except Exception:
                            pass

        for analysis in enriched_ips:
            ip = analysis.get("ip", "")
            if analysis.get("is_bot"):
                bot_count += sum(1 for e in entries if e["ip"] == ip)
            elif analysis.get("is_bot") is False:
                human_count += sum(1 for e in entries if e["ip"] == ip)
    else:
        # Fallback without IP analysis
        enriched_ips = [
            {"ip": ip, "requests": count}
            for ip, count in ip_counter.most_common(10)
        ]

    # Count pages/endpoints
    page_counter = Counter(entry["path"] for entry in entries)

    # Count status codes
    status_counter = Counter(entry["status"] for entry in entries)

    # Get top pages with request counts
    top_pages = [
        {"path": path, "requests": count}
        for path, count in page_counter.most_common(10)
    ]

    # Convert status codes to dict
    status_codes = dict(status_counter)

    # Calculate bot percentage
    total_requests = len(entries)
    bot_percentage = round((bot_count / total_requests * 100), 1) if total_requests > 0 else 0

    return {
        "top_ips": enriched_ips[:10],  # Return top 10
        "top_pages": top_pages,
        "status_codes": status_codes,
        "total_requests": total_requests,
        "unique_visitors": len(ip_counter),
        "bot_stats": {
            "total_bots": bot_count,
            "total_humans": human_count,
            "bot_percentage": bot_percentage
        }
    }
