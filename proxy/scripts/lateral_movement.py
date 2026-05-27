#!/usr/bin/env python3
"""
Lateral Movement Attack Simulation Script
Simulates an attacker moving between systems after initial compromise
"""

import requests
import time
import random
import argparse
import sys
from urllib.parse import urljoin
import json

def simulate_lateral_movement(proxy_url, source_user, target_users, iterations=8):
    """
    Simulates lateral movement by impersonating different users
    and accessing resources across different systems
    """
    print(f"Starting lateral movement simulation against {proxy_url}")
    print(f"Source user: {source_user}")
    print(f"Target users: {', '.join(target_users)}")
    
    # Simulate different session tokens for each user
    user_sessions = {user: f"session_{user}_{random.randint(1000, 9999)}" for user in target_users}
    user_sessions[source_user] = f"session_{source_user}_{random.randint(1000, 9999)}"
    
    # Common endpoints that might be accessed during lateral movement
    endpoints = [
        '/api/users/{target_user}',
        '/api/profile/{target_user}',
        '/api/documents/shared',
        '/admin/access',
        '/api/config',
        '/api/database',
        '/api/system',
        '/api/backups',
        '/api/logs',
        '/api/messages/inbox',
        '/api/files/personal',
        '/api/applications'
    ]
    
    for i in range(iterations):
        # Select a random target user
        target_user = random.choice(list(user_sessions.keys()))
        session_token = user_sessions[target_user]
        
        # Select a random endpoint and format it
        endpoint_template = random.choice(endpoints)
        endpoint = endpoint_template.format(target_user=target_user)
        
        # Add headers that might bypass some security checks
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Authorization': f'Bearer {session_token}',
            'X-Forwarded-For': f'10.0.{random.randint(0, 255)}.{random.randint(1, 254)}',  # Spoof IP
            'X-Original-User': source_user,  # Attempt to spoof original user
        }
        
        target_url = urljoin(proxy_url, endpoint)
        
        try:
            # Use GET for most requests as it's more common
            response = requests.get(target_url, headers=headers, timeout=5)
            
            status = response.status_code
            print(f"Iteration {i+1}: User {target_user} accessing {endpoint} -> {status}")
            
            # Occasionally perform POST requests to simulate more aggressive activity
            if random.random() > 0.7:
                post_headers = headers.copy()
                post_headers['Content-Type'] = 'application/json'
                
                post_data = {
                    'action': 'access_resource',
                    'resource': endpoint,
                    'impersonated_user': source_user,
                    'timestamp': time.time()
                }
                
                post_response = requests.post(target_url, headers=post_headers, json=post_data, timeout=5)
                print(f"  POST {endpoint} -> {post_response.status_code}")
            
            # Random delay to simulate human behavior
            time.sleep(random.uniform(0.3, 1.5))
            
        except requests.exceptions.RequestException as e:
            print(f"Iteration {i+1}: Error accessing {endpoint} as {target_user} - {str(e)}")
    
    print("\nLateral movement simulation completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simulate lateral movement attack')
    parser.add_argument('--proxy-url', default='http://localhost:8080', help='Proxy URL (default: http://localhost:8080)')
    parser.add_argument('--source-user', default='attacker', help='Source compromised user (default: attacker)')
    parser.add_argument('--target-users', nargs='+', default=['user1', 'admin', 'dbadmin'], 
                       help='Target users to impersonate (default: user1 admin dbadmin)')
    parser.add_argument('--iterations', type=int, default=8, help='Number of requests to send (default: 8)')
    
    args = parser.parse_args()
    
    simulate_lateral_movement(args.proxy_url, args.source_user, args.target_users, args.iterations)