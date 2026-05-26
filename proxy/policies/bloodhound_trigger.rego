package bloodhound

import data.bloodhound.tracker

# Default to allowing requests unless they trigger specific defenses
default allow = true

# Attack patterns that should trigger defensive actions
attack_patterns = {
    "directory_traversal": {"../", "..\\", "%2e%2e%2f", "%2e%2e%5c"},
    "sql_injection": {"union select", "drop table", "exec(", "' OR '1'='1"},
    "xss_attempt": {"<script", "javascript:", "onerror=", "<img src="},
    "admin_access": {"/admin", "/login", "/dashboard", "/config"},
    "api_abuse": {"/api/keys", "/api/users", "/api/admin"},
    "honeypot_hit": {"canary-", "honeytoken-", "tripwire-"}
}

# Trigger defensive action if request matches attack patterns
deny {
    input.path
    some pattern_set in attack_patterns
    some pattern in pattern_set
    contains_lower(input.path, pattern)
}

deny {
    input.headers
    some header_value in values(input.headers)
    some pattern_set in attack_patterns
    some pattern in pattern_set
    contains_lower(to_string(header_value), pattern)
}

# Lateral movement detection
lateral_movement_detected {
    input.session_id
    input.previous_paths
    count(input.previous_paths) >= 3
    admin_path_count := count_admin_paths(input.previous_paths)
    admin_path_count >= 2
}

# Trigger when accessing multiple admin-like paths in short succession
deny {
    lateral_movement_detected
}

# Honeypot detection
honeypot_access {
    input.path
    some honeypot_pattern in attack_patterns.honeypot_hit
    contains_lower(input.path, honeypot_pattern)
}

# Deny access to honeypot paths
deny {
    honeypot_access
}

# Additional defensive triggers
defensive_action_required {
    input.risk_score
    input.risk_score > 7.0
}

deny {
    defensive_action_required
}

# Helper function to check if string contains substring (case insensitive)
contains_lower(str, substr) {
    lower_str := lower(str)
    lower_substr := lower(substr)
    contains(lower_str, lower_substr)
}

# Count admin-like paths in history
count_admin_paths(paths) = count_admin {
    admin_paths := [path | path := paths[_]; is_admin_path(path)]
    count_admin := count(admin_paths)
}

# Check if path is admin-like
is_admin_path(path) {
    admin_indicators := {"/admin", "/login", "/dashboard", "/config", "/manager", "/control"}
    some indicator in admin_indicators
    contains_lower(path, indicator)
}

# Bloodhound-specific policies
bloodhound_alert_required {
    input.threat_type
    input.confidence
    input.confidence > 0.8
    input.threat_type == "lateral_movement"
}

bloodhound_alert_required {
    input.threat_type
    input.confidence
    input.confidence > 0.9
    input.threat_type == "honeytrap_access"
}

# Self-healing actions
self_healing_required {
    input.attack_path_score
    input.attack_path_score > 8.0
}

# Return enhanced security response for high-risk requests
enhanced_security_check {
    input.risk_assessment
    input.risk_assessment.level == "critical"
}

# Default allow for normal requests
allow {
    not deny
    not enhanced_security_check
}