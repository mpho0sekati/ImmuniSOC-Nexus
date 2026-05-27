#!/usr/bin/env python3
"""
Insider Attack Simulation Script
Simulates an insider threat scenario where a legitimate user performs malicious activities
"""

import requests
import time
import random
import argparse
import sys
from urllib.parse import urljoin
import json

def simulate_insider_attack(proxy_url, username, iterations=10):
    """
    Simulates an insider attack by performing legitimate-looking requests
    mixed with suspicious activities
    """
    print(f"Starting insider attack simulation against {proxy_url}")
    print(f"Target user: {username}")
    
    # Common headers that mimic legitimate user behavior
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Authorization': f'Bearer mock_token_for_{username}',  # Simulate authenticated session
        'X-Requested-With': 'XMLHttpRequest'
    }
    
    endpoints = [
        '/api/dashboard',
        '/api/profile',
        '/api/settings',
        '/admin/users',  # Suspicious admin access
        '/api/logs',     # Accessing sensitive logs
        '/config/db',    # Attempting to access DB config
        '/api/data/export',  # Data exfiltration attempt
        '/admin/system', # Administrative access
    ]
    
    # Simulate normal and suspicious activity
    for i in range(iterations):
        # Randomly select an endpoint
        endpoint = random.choice(endpoints)
        target_url = urljoin(proxy_url, endpoint)
        
        # Determine if this request is suspicious based on endpoint
        is_suspicious = any(susp in endpoint for susp in ['/admin', '/config', '/export'])
        
        # Randomly select HTTP method
        method = random.choice(['GET', 'POST', 'PUT']) if not is_suspicious else 'GET'
        
        try:
            if method == 'GET':
                response = requests.get(target_url, headers=headers, timeout=5)
            elif method == 'POST':
                # For POST requests, send some realistic data
                post_data = {
                    'user': username,
                    'action': 'update_settings' if not is_suspicious else 'access_admin',
                    'timestamp': time.time()
                }
                response = requests.post(target_url, headers=headers, json=post_data, timeout=5)
            elif method == 'PUT':
                put_data = {
                    'user': username,
                    'updates': {'profile': 'normal'} if not is_suspicious else {'permissions': 'admin'}
                }
                response = requests.put(target_url, headers=headers, json=put_data, timeout=5)
            
            status = response.status_code
            print(f"Iteration {i+1}: {method} {endpoint} -> {status}")
            
            # Add some delay to mimic human behavior
            time.sleep(random.uniform(0.5, 2.0))
            
        except requests.exceptions.RequestException as e:
            print(f"Iteration {i+1}: Error accessing {endpoint} - {str(e)}")
    
    print("\nInsider attack simulation completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simulate an insider attack')
    parser.add_argument('--proxy-url', default='http://localhost:8080', help='Proxy URL (default: http://localhost:8080)')
    parser.add_argument('--username', default='employee_john', help='Username to simulate (default: employee_john)')
    parser.add_argument('--iterations', type=int, default=10, help='Number of requests to send (default: 10)')
    
    args = parser.parse_args()
    
    simulate_insider_attack(args.proxy_url, args.username, args.iterations)