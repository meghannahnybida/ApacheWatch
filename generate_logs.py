#!/usr/bin/env python3
"""Generate fake Apache access logs spanning multiple days for testing."""

import random
from datetime import datetime, timedelta

# Sample data - Human IPs (residential/ISP)
human_ips = [
    "192.168.1.100", "192.168.1.101", "10.0.0.50",  # Local network
    "73.162.225.100",   # Comcast
    "98.97.44.33",      # Verizon
    "24.18.200.150",    # Charter/Spectrum
    "99.45.32.101",     # Comcast
]

# Bot IPs (search engines, crawlers) - these have reverse DNS
bot_ips = [
    "66.249.66.1",      # Googlebot (crawl-66-249-66-1.googlebot.com)
    "66.249.73.135",    # Googlebot
    "157.55.39.112",    # Bingbot (msnbot-157-55-39-112.search.msn.com)
    "40.77.167.40",     # Bingbot
    "17.58.99.244",     # Applebot
    "54.36.148.120",    # OVH/Scrapers
    "207.46.13.50",     # MSN Bot
]

paths = [
    "/", "/index.html", "/about.html", "/contact.html",
    "/api/users", "/api/products", "/api/orders",
    "/images/logo.png", "/css/style.css", "/js/app.js",
    "/admin/login", "/admin/dashboard", "/search",
    "/blog/post-1", "/blog/post-2", "/products/item-123",
    "/robots.txt", "/sitemap.xml"  # Common bot targets
]

# Human user agents (real browsers)
human_user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
]

# Bot user agents (crawlers and bots)
bot_user_agents = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/W.X.Y.Z Safari/537.36",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "curl/7.68.0",
    "Python-requests/2.28.1",
]

# Generate logs
def generate_log_line(timestamp, is_bot=False):
    """Generate a single Apache access log line."""
    # Select IP and user agent based on whether it's a bot
    if is_bot:
        ip = random.choice(bot_ips)
        user_agent = random.choice(bot_user_agents)
        # Bots often request specific paths
        path_pool = paths if random.random() > 0.3 else ["robots.txt", "/sitemap.xml", "/", "/blog/post-1", "/blog/post-2"]
        path = random.choice(path_pool)
    else:
        ip = random.choice(human_ips)
        user_agent = random.choice(human_user_agents)
        path = random.choice(paths)
    
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
        
        # Determine if this request is from a bot (20% bot traffic during day, 40% at night)
        is_bot = random.random() < 0.20
        
        # Weight towards business hours (more traffic 9am-5pm)
        if 9 <= hour <= 17:
            # More likely to generate requests during business hours
            if random.random() > 0.3:  # 70% chance
                timestamp = day_start.replace(hour=hour, minute=minute, second=second)
                logs.append((timestamp, generate_log_line(timestamp, is_bot)))
        else:
            # Less traffic outside business hours (more bots at night)
            if random.random() > 0.7:  # 30% chance
                is_bot = random.random() < 0.40  # Higher bot ratio at night
                timestamp = day_start.replace(hour=hour, minute=minute, second=second)
                logs.append((timestamp, generate_log_line(timestamp, is_bot)))

# Sort logs by timestamp
logs.sort(key=lambda x: x[0])

# Write to file
with open(output_file, 'w') as f:
    for _, log_line in logs:
        f.write(log_line)

print(f"Generated {len(logs)} log entries spanning 5 days")
print(f"Written to: {output_file}")
print(f"Date range: {logs[0][0].strftime('%Y-%m-%d')} to {logs[-1][0].strftime('%Y-%m-%d')}")
