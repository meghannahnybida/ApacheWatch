#!/usr/bin/env python3
"""Generate fake Apache access logs spanning multiple days for testing."""

import random
from datetime import datetime, timedelta

# Sample data
ips = [
    "192.168.1.100", "192.168.1.101", "192.168.1.102", 
    "10.0.0.50", "10.0.0.51", "172.16.0.10",
    "203.0.113.45", "198.51.100.22", "198.51.100.23"
]

paths = [
    "/", "/index.html", "/about.html", "/contact.html",
    "/api/users", "/api/products", "/api/orders",
    "/images/logo.png", "/css/style.css", "/js/app.js",
    "/admin/login", "/admin/dashboard", "/search",
    "/blog/post-1", "/blog/post-2", "/products/item-123"
]

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15",
    "curl/7.68.0",
    "Python-requests/2.28.1"
]

# Generate logs
def generate_log_line(timestamp):
    """Generate a single Apache access log line."""
    ip = random.choice(ips)
    path = random.choice(paths)
    user_agent = random.choice(user_agents)
    
    # Status code distribution (mostly success, some errors)
    status_pool = [200] * 70 + [304] * 15 + [404] * 10 + [500] * 3 + [301] * 2
    status = random.choice(status_pool)
    
    # Size varies by status
    if status == 200:
        size = random.randint(1000, 50000)
    elif status == 304:
        size = 0
    elif status == 404:
        size = random.randint(200, 1000)
    else:
        size = random.randint(500, 5000)
    
    # Format timestamp
    ts_str = timestamp.strftime('%d/%b/%Y:%H:%M:%S +0000')
    
    # Build log line
    log_line = f'{ip} - - [{ts_str}] "GET {path} HTTP/1.1" {status} {size} "-" "{user_agent}"\n'
    
    return log_line

# Generate logs for multiple days
output_file = "./logs/access.log"

print("Generating multi-day Apache access logs...")

# Start from 5 days ago
start_date = datetime.now() - timedelta(days=5)
current_time = start_date

logs = []

# Generate logs for 5 days
for day in range(5):
    day_start = start_date + timedelta(days=day)
    
    # Vary requests per day
    requests_per_day = random.randint(500, 1200)
    
    for _ in range(requests_per_day):
        # Generate random time within the day
        hour = random.randint(0, 23)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        
        # Weight towards business hours (more traffic 9am-5pm)
        if 9 <= hour <= 17:
            # More likely to generate requests during business hours
            if random.random() > 0.3:  # 70% chance
                timestamp = day_start.replace(hour=hour, minute=minute, second=second)
                logs.append((timestamp, generate_log_line(timestamp)))
        else:
            # Less traffic outside business hours
            if random.random() > 0.7:  # 30% chance
                timestamp = day_start.replace(hour=hour, minute=minute, second=second)
                logs.append((timestamp, generate_log_line(timestamp)))

# Sort logs by timestamp
logs.sort(key=lambda x: x[0])

# Write to file
with open(output_file, 'w') as f:
    for _, log_line in logs:
        f.write(log_line)

print(f"Generated {len(logs)} log entries spanning 5 days")
print(f"Written to: {output_file}")
print(f"Date range: {logs[0][0].strftime('%Y-%m-%d')} to {logs[-1][0].strftime('%Y-%m-%d')}")
