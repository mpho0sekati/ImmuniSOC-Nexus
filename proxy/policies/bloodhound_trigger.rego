package authz

# Deny if the risk score from Bloodhound exceeds the threshold
allow = false {
    input.risk_score > 7.0
}

# Deny if a specific honeytrap access is detected
allow = false {
    input.threat_type == "honeytrap_access"
}

# Deny if high-risk lateral movement is detected with high confidence
allow = false {
    input.threat_type == "lateral_movement"
    input.attack_path_score > 8.0
    input.confidence > 0.9
}

# Default allow for normal requests that don't match deny conditions
default allow = true