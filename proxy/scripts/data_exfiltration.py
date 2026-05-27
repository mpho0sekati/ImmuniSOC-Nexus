#!/usr/bin/env python3
"""
Data Exfiltration Attack Simulation Script
Simulates an attacker attempting to extract sensitive data from the system
"""

import requests
import time
import random
import argparse
import sys
from urllib.parse import urljoin
import json
import base64

def simulate_data_exfiltration(proxy_url, iterations=12):
    """
    Simulates data exfiltration by making requests to export, download,
    or access sensitive data endpoints
    """
    print(f"Starting data exfiltration simulation against {proxy_url}")
    
    # Headers to make requests appear more legitimate
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Authorization': 'Bearer legitimate_user_session_token',
        'Content-Type': 'application/json',
    }
    
    # Simulated sensitive data payloads
    sensitive_payloads = [
        {
            'query': 'SELECT * FROM users LIMIT 1000',
            'format': 'json',
            'export_type': 'user_data'
        },
        {
            'query': 'SELECT * FROM financial_records WHERE date > "2023-01-01"',
            'format': 'csv',
            'export_type': 'financial'
        },
        {
            'query': 'SELECT * FROM customer_pii',
            'format': 'xml',
            'export_type': 'pii'
        },
        {
            'query': 'SELECT password_hash, user_id FROM auth_table',
            'format': 'json',
            'export_type': 'credentials'
        },
        {
            'report_type': 'system_logs',
            'date_range': 'last_30_days',
            'format': 'zip'
        },
        {
            'action': 'backup_db',
            'database': 'production',
            'compress': True
        }
    ]
    
    # Endpoints commonly used for data export/extraction
    endpoints = [
        '/api/data/export',
        '/api/reports/generate',
        '/api/backup/create',
        '/api/download/data',
        '/admin/export/users',
        '/api/query/execute',
        '/api/files/download',
        '/admin/logs/export',
        '/api/search/results',
        '/api/documents/export',
        '/api/analytics/download'
    ]
    
    for i in range(iterations):
        # Select random endpoint and payload
        endpoint = random.choice(endpoints)
        payload = random.choice(sensitive_payloads)
        
        target_url = urljoin(proxy_url, endpoint)
        
        try:
            # Randomly decide to use GET or POST based on the endpoint
            if any(keyword in endpoint.lower() for keyword in ['export', 'download', 'backup']):
                # Use GET for download-like endpoints
                params = dict(payload)  # Convert to URL parameters
                response = requests.get(target_url, headers=headers, params=params, timeout=10)
            else:
                # Use POST for query-like endpoints
                response = requests.post(target_url, headers=headers, json=payload, timeout=10)
            
            status = response.status_code
            print(f"Iteration {i+1}: {response.request.method} {endpoint} -> {status}")
            
            # Add extra headers to try to bypass egress protection
            if random.random() > 0.5:
                extra_headers = headers.copy()
                extra_headers.update({
                    'X-Request-Purpose': 'legitimate_business_need',
                    'X-PopIA-Purpose': 'data_analysis',  # Try to bypass POPIA checks
                    'X-Forwarded-Host': 'trusted-partner.com',
                    'Referer': 'https://legitimate-business-site.com/approved-page'
                })
                
                # Make another request with extra headers
                if response.request.method == 'GET':
                    extra_response = requests.get(target_url, headers=extra_headers, params=params, timeout=10)
                else:
                    extra_response = requests.post(target_url, headers=extra_headers, json=payload, timeout=10)
                    
                print(f"  With extra headers -> {extra_response.status_code}")
            
            # Simulate large data requests occasionally
            if random.random() > 0.7:
                large_payload = {
                    **payload,
                    'limit': 10000,  # Request large amount of data
                    'offset': random.randint(0, 5000),
                    'include_nested': True,
                    'compress': True
                }
                
                large_response = requests.post(target_url, headers=headers, json=large_payload, timeout=15)
                print(f"  Large data request -> {large_response.status_code}")
            
            # Random delay to simulate real-world timing
            time.sleep(random.uniform(0.5, 2.5))
            
        except requests.exceptions.RequestException as e:
            print(f"Iteration {i+1}: Error accessing {endpoint} - {str(e)}")
    
    print("\nData exfiltration simulation completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simulate data exfiltration attack')
    parser.add_argument('--proxy-url', default='http://localhost:8080', help='Proxy URL (default: http://localhost:8080)')
    parser.add_argument('--iterations', type=int, default=12, help='Number of requests to send (default: 12)')
    
    args = parser.parse_args()
    
    simulate_data_exfiltration(args.proxy_url, args.iterations)