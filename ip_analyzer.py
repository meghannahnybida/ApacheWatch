#!/usr/bin/env python3
"""
IP Analysis Module - Hostname, ISP, and Bot Detection
Identifies visitors by reverse DNS lookup and hostname patterns.
"""

import socket
import re
from functools import lru_cache

# Known bot hostname patterns
BOT_PATTERNS = {
    'googlebot.com': {'name': 'Googlebot', 'org': 'Google LLC', 'type': 'Search Engine'},
    'google.com': {'name': 'Google', 'org': 'Google LLC', 'type': 'Search Engine'},
    'crawl.baidu.com': {'name': 'Baiduspider', 'org': 'Baidu', 'type': 'Search Engine'},
    'search.msn.com': {'name': 'Bingbot', 'org': 'Microsoft', 'type': 'Search Engine'},
    'bingbot': {'name': 'Bingbot', 'org': 'Microsoft', 'type': 'Search Engine'},
    'yahoo.net': {'name': 'Yahoo Slurp', 'org': 'Yahoo', 'type': 'Search Engine'},
    'yandex.com': {'name': 'YandexBot', 'org': 'Yandex', 'type': 'Search Engine'},
    'applebot': {'name': 'Applebot', 'org': 'Apple Inc.', 'type': 'Search Engine'},
    'facebook.com': {'name': 'Facebook Bot', 'org': 'Meta', 'type': 'Social Media'},
    'twitter.com': {'name': 'Twitterbot', 'org': 'Twitter', 'type': 'Social Media'},
    'linkedin.com': {'name': 'LinkedIn Bot', 'org': 'LinkedIn', 'type': 'Social Media'},
    'amazonaws.com': {'name': 'AWS Bot/Service', 'org': 'Amazon Web Services', 'type': 'Cloud/Bot'},
    'googleusercontent.com': {'name': 'Google Cloud', 'org': 'Google LLC', 'type': 'Cloud/Bot'},
    'compute.amazonaws.com': {'name': 'AWS EC2', 'org': 'Amazon Web Services', 'type': 'Cloud/Bot'},
    'ovh.net': {'name': 'OVH Cloud', 'org': 'OVH', 'type': 'Hosting/Bot'},
    'scoutjet.com': {'name': 'ScoutJet', 'org': 'Scoutjet', 'type': 'Crawler'},
    'archive.org': {'name': 'Internet Archive Bot', 'org': 'Internet Archive', 'type': 'Crawler'},
    'ahrefsbot': {'name': 'AhrefsBot', 'org': 'Ahrefs', 'type': 'SEO Crawler'},
    'semrush.com': {'name': 'SemrushBot', 'org': 'Semrush', 'type': 'SEO Crawler'},
    'mj12bot': {'name': 'MJ12bot', 'org': 'Majestic', 'type': 'SEO Crawler'},
}

# User agent bot patterns
BOT_USER_AGENTS = [
    'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python-requests',
    'http', 'urllib', 'scrapy', 'headless', 'phantom', 'selenium'
]

@lru_cache(maxsize=256)
def get_hostname(ip_address):
    """
    Get hostname via reverse DNS lookup. Cached for performance.
    
    Args:
        ip_address: IP address string
        
    Returns:
        Hostname string or None if lookup fails
    """
    try:
        # Set a timeout to prevent hanging
        socket.setdefaulttimeout(2)
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname.lower()
    except (socket.herror, socket.gaierror, socket.timeout):
        return None
    except Exception:
        return None

def is_private_ip(ip_address):
    """Check if IP is in private/local ranges."""
    if ip_address.startswith('192.168.') or \
       ip_address.startswith('10.') or \
       ip_address.startswith('172.16.') or \
       ip_address.startswith('127.') or \
       ip_address == 'localhost':
        return True
    return False

def identify_from_hostname(hostname):
    """
    Identify bot status from hostname.
    
    Args:
        hostname: Hostname string
        
    Returns:
        Dictionary with bot info
    """
    if not hostname:
        return {
            'is_bot': None,
            'bot_name': None,
            'bot_type': None
        }
    
    # Check against known bot patterns
    for pattern, info in BOT_PATTERNS.items():
        if pattern in hostname:
            return {
                'is_bot': True,
                'bot_name': info['name'],
                'bot_type': info['type']
            }
    
    return {
        'is_bot': False,
        'bot_name': None,
        'bot_type': None
    }

def identify_from_user_agent(user_agent):
    """
    Identify bot from user agent string.
    
    Args:
        user_agent: User-Agent header string
        
    Returns:
        Dictionary with bot detection info
    """
    if not user_agent:
        return {'is_bot': None, 'reason': 'No user agent'}
    
    ua_lower = user_agent.lower()
    
    # Check for bot patterns in user agent
    for bot_pattern in BOT_USER_AGENTS:
        if bot_pattern in ua_lower:
            # Identify specific bot type
            if 'googlebot' in ua_lower:
                return {'is_bot': True, 'reason': 'Googlebot user agent', 'bot_name': 'Googlebot'}
            elif 'bingbot' in ua_lower:
                return {'is_bot': True, 'reason': 'Bingbot user agent', 'bot_name': 'Bingbot'}
            elif 'curl' in ua_lower:
                return {'is_bot': True, 'reason': 'cURL tool', 'bot_name': 'cURL'}
            elif 'python' in ua_lower:
                return {'is_bot': True, 'reason': 'Python script', 'bot_name': 'Python Script'}
            else:
                return {'is_bot': True, 'reason': f'Bot pattern: {bot_pattern}', 'bot_name': 'Bot'}
    
    return {'is_bot': False, 'reason': 'Normal browser'}

def analyze_ip_visitor(ip_address, user_agent=None):
    """
    Complete analysis of an IP visitor with hostname and ISP detection.
    
    Args:
        ip_address: IP address string
        user_agent: Optional User-Agent string
        
    Returns:
        Dictionary with complete visitor analysis
    """
    analysis = {
        'ip': ip_address,
        'is_private': is_private_ip(ip_address),
        'hostname': None,
        'is_bot': None,
        'bot_name': None,
        'bot_type': None,
        'confidence': 'unknown'
    }
    
    # Handle private IPs
    if analysis['is_private']:
        analysis['is_bot'] = False
        analysis['confidence'] = 'high'
        return analysis
    
    # Get hostname via reverse DNS
    hostname = get_hostname(ip_address)
    analysis['hostname'] = hostname
    
    # Identify from hostname
    hostname_info = identify_from_hostname(hostname)
    analysis.update(hostname_info)
    
    # Cross-check with user agent
    if user_agent:
        ua_info = identify_from_user_agent(user_agent)
        
        # If user agent says it's a bot, trust it
        if ua_info['is_bot']:
            analysis['is_bot'] = True
            if not analysis['bot_name']:
                analysis['bot_name'] = ua_info.get('bot_name', 'Bot')
            analysis['confidence'] = 'high'
            analysis['ua_reason'] = ua_info.get('reason')
        elif analysis['is_bot'] is None:
            # User agent suggests human
            analysis['is_bot'] = False
            analysis['confidence'] = 'medium'
    
    # Set confidence based on what we know
    if analysis['is_bot'] and hostname and any(p in hostname for p in BOT_PATTERNS.keys()):
        analysis['confidence'] = 'high'
    elif analysis['is_bot'] is None:
        analysis['confidence'] = 'low'
    
    return analysis

def get_visitor_summary(access_log_entries):
    """
    Analyze multiple access log entries and provide visitor summary.
    
    Args:
        access_log_entries: List of parsed access log entries
        
    Returns:
        Dictionary with visitor statistics
    """
    from collections import Counter
    
    visitors = {}
    bot_count = 0
    human_count = 0
    bot_types = Counter()
    
    for entry in access_log_entries:
        ip = entry.get('ip')
        user_agent = entry.get('user_agent')
        
        if not ip:
            continue
        
        # Analyze visitor (cache results per IP)
        if ip not in visitors:
            visitors[ip] = analyze_ip_visitor(ip, user_agent)
        
        visitor = visitors[ip]
        
        # Count bots vs humans
        if visitor.get('is_bot'):
            bot_count += 1
            bot_type = visitor.get('bot_type', 'Unknown Bot')
            bot_types[bot_type] += 1
        elif visitor.get('is_bot') == False:
            human_count += 1
    
    return {
        'total_visitors': len(visitors),
        'bot_requests': bot_count,
        'human_requests': human_count,
        'bot_types': dict(bot_types.most_common(10)),
        'visitor_details': list(visitors.values())
    }
