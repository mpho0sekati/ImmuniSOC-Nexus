#!/usr/bin/env python3
"""
Normal Traffic Simulation Script
Simulates legitimate user traffic to establish baseline behavior
"""

import requests
import time
import random
import argparse
import sys
from urllib.parse import urljoin
import json

def simulate_normal_traffic(proxy_url, num_users=5, requests_per_user=10):
    """
    Simulates normal, legitimate traffic patterns from multiple users
    """
    print(f"Starting normal traffic simulation against {proxy_url}")
    print(f"Simulating {num_users} users with {requests_per_user} requests each")
    
    # Simulate different legitimate users
    users = [f'user_{i}' for i in range(1, num_users + 1)]
    sessions = {user: f'session_{user}_{random.randint(10000, 99999)}' for user in users}
    
    # Common legitimate endpoints
    endpoints = [
        '/api/dashboard',
        '/api/profile',
        '/api/messages',
        '/api/documents',
        '/api/calendar',
        '/api/tasks',
        '/api/settings',
        '/api/preferences',
        '/api/history',
        '/api/search',
        '/api/projects',
        '/api/teams',
        '/api/files',
        '/api/activity',
        '/api/notifications'
    ]
    
    # Legitimate user agents
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
    ]
    
    total_requests = 0
    
    for user in users:
        print(f"\nSimulating traffic for {user}...")
        session_token = sessions[user]
        
        for req_num in range(requests_per_user):
            # Select random endpoint
            endpoint = random.choice(endpoints)
            target_url = urljoin(proxy_url, endpoint)
            
            # Random legitimate headers
            headers = {
                'User-Agent': random.choice(user_agents),
                'Accept': 'application/json, text/html, */*',
                'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'en-CA,en;q=0.7']),
                'Authorization': f'Bearer {session_token}',
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': f'https://legitimate-site.com/app{random.choice(["", "/dashboard", "/home", "/settings"])}'
            }
            
            # Determine request method based on endpoint
            if any(keyword in endpoint for keyword in ['login', 'logout', 'create', 'update', 'delete', 'upload']):
                method = 'POST'
            elif any(keyword in endpoint for keyword in ['search', 'filter', 'query']):
                method = 'GET'
            else:
                method = random.choice(['GET', 'POST'])
            
            try:
                if method == 'GET':
                    # Add some random query parameters for realism
                    params = {}
                    if random.random() > 0.3:
                        params['page'] = random.randint(1, 5)
                        params['limit'] = random.randint(10, 50)
                    if random.random() > 0.5:
                        params['sort'] = random.choice(['date', 'name', 'priority'])
                    
                    response = requests.get(target_url, headers=headers, params=params, timeout=5)
                else:
                    # Create realistic POST data based on endpoint
                    post_data = {
                        'user_id': user,
                        'timestamp': time.time(),
                        'session_id': session_token
                    }
                    
                    if 'settings' in endpoint:
                        post_data['settings'] = {
                            'theme': random.choice(['light', 'dark']),
                            'notifications': random.choice([True, False]),
                            'language': 'en'
                        }
                    elif 'messages' in endpoint:
                        post_data['message'] = {
                            'subject': f'Message from {user}',
                            'body': f'Hi, this is a normal message from {user}',
                            'recipient': random.choice(users)
                        }
                    elif 'tasks' in endpoint:
                        post_data['task'] = {
                            'title': f'Task for {user}',
                            'description': f'This is a sample task assigned to {user}',
                            'priority': random.choice(['low', 'medium', 'high'])
                        }
                    
                    response = requests.post(target_url, headers=headers, json=post_data, timeout=5)
                
                status = response.status_code
                print(f"  Request {req_num + 1}: {method} {endpoint} -> {status}")
                
                total_requests += 1
                
                # Realistic delays between requests
                delay = random.uniform(1.0, 5.0)  # Longer delays for normal traffic
                time.sleep(delay)
                
            except requests.exceptions.RequestException as e:
                print(f"  Request {req_num + 1}: Error accessing {endpoint} - {str(e)}")
    
    print(f"\nNormal traffic simulation completed.")
    print(f"Total requests sent: {total_requests}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simulate normal traffic patterns')
    parser.add_argument('--proxy-url', default='http://localhost:8080', help='Proxy URL (default: http://localhost:8080)')
    parser.add_argument('--num-users', type=int, default=5, help='Number of simulated users (default: 5)')
    parser.add_argument('--requests-per-user', type=int, default=10, help='Requests per user (default: 10)')
    
    args = parser.parse_args()
    
    simulate_normal_traffic(args.proxy_url, args.num_users, args.requests_per_user)