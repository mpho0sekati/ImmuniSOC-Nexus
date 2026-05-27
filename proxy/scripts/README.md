# ImmuniSOC-Nexus: Attack Simulation Scripts

This directory contains various attack simulation scripts designed to test the ImmuniSOC-Nexus security platform.

## Available Scripts

### 1. Insider Attack Simulation (`insider_attack.py`)
Simulates an insider threat where a legitimate user performs malicious activities.

Usage:
```bash
python insider_attack.py --proxy-url http://localhost:8080 --username employee_john --iterations 10
```

### 2. Lateral Movement Simulation (`lateral_movement.py`)
Simulates an attacker moving between systems after initial compromise.

Usage:
```bash
python lateral_movement.py --proxy-url http://localhost:8080 --source-user attacker --target-users user1 admin dbadmin --iterations 8
```

### 3. Data Exfiltration Simulation (`data_exfiltration.py`)
Simulates attempts to extract sensitive data from the system.

Usage:
```bash
python data_exfiltration.py --proxy-url http://localhost:8080 --iterations 12
```

### 4. Honeytoken Detection Simulation (`honeytoken_detection.py`)
Tests the system's ability to detect when honeytokens are accessed.

Usage:
```bash
python honeytoken_detection.py --proxy-url http://localhost:8080 --iterations 15
```

### 5. Normal Traffic Simulation (`normal_traffic.py`)
Simulates legitimate user traffic to establish baseline behavior.

Usage:
```bash
python normal_traffic.py --proxy-url http://localhost:8080 --num-users 5 --requests-per-user 10
```

### 6. Penetration Test Simulation (`pen_test_simulation.py`)
Combines all attack types in a coordinated simulation.

Usage:
```bash
python pen_test_simulation.py --proxy-url http://localhost:8080 --duration 10
```

## Requirements

- Python 3.6+
- `requests` library (`pip install requests`)

## Purpose

These scripts are designed to:
- Test the effectiveness of the ImmuniSOC-Nexus security controls
- Validate that detection mechanisms are working properly
- Assess the response capabilities of the T-Cell Self-Healing Engine
- Evaluate the effectiveness of deception elements
- Verify the integrity of the Monocyte Immutable Logging system
- Monitor the dashboard for real-time visualization of threats

## Important Notes

- These scripts are intended for authorized testing only
- Ensure you have permission to run these tests against target systems
- Results should be analyzed using the ImmuniSOC-Nexus dashboard
- All activities are logged for audit and compliance purposes