package authz

import rego.v1

# Default deny policy - fail-closed security model
default allow = false

# Define sensitive data patterns for egress detection
sensitive_patterns = [
    # Credit card patterns (Visa, Mastercard, Amex, etc.)
    "(?i)\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13})\\b",
    # SSN patterns
    "(?i)\\b\\d{3}-\\d{2}-\\d{4}\\b",
    # Email addresses
    "(?i)\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
    # Passport numbers (generic pattern)
    "(?i)\\b[A-Za-z]{1,2}[0-9]{6,8}\\b",
    # Phone numbers
    "(?i)\\b\\+?[1-9]\\d{1,14}\\b",
    # Password fields
    "(?i)(password|pwd|pass)",
    # Database connection strings
    "(?i)(connection|string|conn)=(.*)",
    # API keys and tokens
    "(?i)(api[_-]?key|token|auth|bearer|secret)=([a-zA-Z0-9-_]+)",
    # Internal IP addresses
    "\\b(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2[0-9]|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b",
    # Authentication headers
    "(?i)(authorization|www-authenticate|proxy-authenticate):",
]

# Function to check if data contains sensitive information
contains_sensitive_data(data) := true {
    some i
    re_match(sensitive_patterns[i], data)
}

# Egress policy - check outbound requests for sensitive data
allow if {
    # Input comes from egress middleware with context
    input.request_method == "EGRESS_CHECK"
    
    # Check if destination is in approved outbound list
    is_approved_destination(input.destination)
    
    # Check if payload contains sensitive data
    not contains_sensitive_payload(input.payload)
    
    # Check if request meets business justification
    has_valid_business_purpose(input.purpose)
}

# Alternative allow condition for admin bypass (with audit trail)
allow if {
    input.is_admin_bypass == true
    input.audit_log_required == true
}

# Function to check if payload contains sensitive data
contains_sensitive_payload(payload) := true {
    # Convert payload to string for pattern matching
    payload_str = sprintf("%v", [payload])
    contains_sensitive_data(payload_str)
}

# Function to check if destination is approved
is_approved_destination(destination) := true {
    # List of approved destinations
    approved_destinations = [
        "https://analytics.company.com",
        "https://logging.company.com", 
        "https://monitoring.company.com",
        "https://backup.company.com",
        "https://updates.company.com"
    ]
    destination in approved_destinations
}

# Function to check if request has valid business purpose
has_valid_business_purpose(purpose) := true {
    valid_purposes = [
        "customer_support",
        "system_monitoring", 
        "performance_metrics",
        "security_alerts",
        "backup_operations",
        "compliance_reporting",
        "business_intelligence"
    ]
    purpose in valid_purposes
}

# Policy for blocking egress based on data classification
block_egress if {
    # If data is classified as CRITICAL and destination is not approved
    input.data_classification == "CRITICAL"
    not is_approved_destination(input.destination)
}

# Policy for blocking egress based on data sensitivity
block_egress if {
    # If payload contains sensitive data and purpose is not justified
    contains_sensitive_payload(input.payload)
    not has_valid_business_purpose(input.purpose)
}

# Policy for blocking egress to suspicious destinations
block_egress if {
    # Check if destination is in deny list
    is_suspicious_destination(input.destination)
}

# Function to check if destination is suspicious
is_suspicious_destination(destination) := true {
    suspicious_domains = [
        "pastebin.com",
        "dropbox.com",
        "onedrive.com", 
        "google.com/drive",
        "mega.nz",
        "send-anywhere.com",
        "we.tl",
        "wetransfer.com"
    ]
    some domain
    domain in suspicious_domains
    contains(destination, domain)
}