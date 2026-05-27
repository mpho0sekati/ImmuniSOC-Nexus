#!/usr/bin/env python3
"""
Final Penetration Test Simulation Script
Combines all attack types in a coordinated simulation
"""

import subprocess
import time
import argparse
import sys
import os
from datetime import datetime

def run_pen_test_simulation(proxy_url, duration_minutes=10):
    """
    Runs a comprehensive penetration test simulation combining all attack types
    """
    print("="*60)
    print("FINAL PENETRATION TEST SIMULATION")
    print("="*60)
    print(f"Target: {proxy_url}")
    print(f"Duration: {duration_minutes} minutes")
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-"*60)
    
    # Define the scripts to run
    scripts = [
        ("insider_attack.py", ["--proxy-url", proxy_url, "--iterations", "20"]),
        ("lateral_movement.py", ["--proxy-url", proxy_url, "--iterations", "15"]),
        ("data_exfiltration.py", ["--proxy-url", proxy_url, "--iterations", "25"]),
        ("honeytoken_detection.py", ["--proxy-url", proxy_url, "--iterations", "20"]),
        ("normal_traffic.py", ["--proxy-url", proxy_url, "--num-users", "3", "--requests-per-user", "15"])
    ]
    
    # Calculate the total runtime in seconds
    total_runtime = duration_minutes * 60
    
    # Calculate how many rounds of all scripts we can run
    # Each round should take approximately 2-3 minutes based on iterations
    approx_round_time = 180  # 3 minutes per round
    num_rounds = max(1, total_runtime // approx_round_time)
    
    print(f"Planning to run {num_rounds} rounds of comprehensive testing...")
    print("-"*60)
    
    start_time = time.time()
    
    for round_num in range(num_rounds):
        print(f"\nRound {round_num + 1}/{num_rounds}")
        print("-" * 30)
        
        for script_name, args in scripts:
            script_path = os.path.join(os.path.dirname(__file__), script_name)
            
            if not os.path.exists(script_path):
                print(f"Warning: Script {script_path} not found, skipping...")
                continue
            
            print(f"Running {script_name}...")
            
            try:
                # Run the script with a timeout
                cmd = ["python", script_path] + args
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # 5 minute timeout per script
                
                if result.returncode == 0:
                    print(f"  ✓ {script_name} completed successfully")
                else:
                    print(f"  ✗ {script_name} failed with exit code {result.returncode}")
                    if result.stderr:
                        print(f"    Error: {result.stderr[:200]}...")  # Show first 200 chars of error
                
            except subprocess.TimeoutExpired:
                print(f"  ⚠ {script_name} timed out after 5 minutes")
            except Exception as e:
                print(f"  ✗ {script_name} encountered an error: {str(e)}")
        
        # Check if we've exceeded the total runtime
        elapsed = time.time() - start_time
        remaining = total_runtime - elapsed
        
        if remaining <= 0:
            print(f"\nReached maximum simulation time ({duration_minutes} minutes)")
            break
        
        # Brief pause between rounds
        if round_num < num_rounds - 1:
            pause_time = min(30, remaining)  # Max 30 seconds between rounds, or remaining time
            print(f"\nPausing for {pause_time}s before next round...")
            time.sleep(pause_time)
    
    elapsed_total = time.time() - start_time
    print("\n" + "="*60)
    print("PENETRATION TEST SIMULATION COMPLETED")
    print("="*60)
    print(f"End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Actual duration: {elapsed_total/60:.1f} minutes")
    print("Simulation logs and metrics should be available in the dashboard")
    print("="*60)

def main():
    parser = argparse.ArgumentParser(description='Run comprehensive penetration test simulation')
    parser.add_argument('--proxy-url', default='http://localhost:8080', 
                       help='Proxy URL to test against (default: http://localhost:8080)')
    parser.add_argument('--duration', type=int, default=10, 
                       help='Duration of simulation in minutes (default: 10)')
    
    args = parser.parse_args()
    
    # Verify that all required scripts exist
    required_scripts = [
        'insider_attack.py',
        'lateral_movement.py', 
        'data_exfiltration.py',
        'honeytoken_detection.py',
        'normal_traffic.py'
    ]
    
    missing_scripts = []
    for script in required_scripts:
        script_path = os.path.join(os.path.dirname(__file__), script)
        if not os.path.exists(script_path):
            missing_scripts.append(script)
    
    if missing_scripts:
        print(f"Error: Missing required scripts: {', '.join(missing_scripts)}")
        print("Please ensure all attack simulation scripts are in the scripts directory.")
        sys.exit(1)
    
    run_pen_test_simulation(args.proxy_url, args.duration)

if __name__ == "__main__":
    main()