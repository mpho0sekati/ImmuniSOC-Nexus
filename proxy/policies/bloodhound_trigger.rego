package authz

import rego.v1

default allow = false

allowed_methods := {"GET", "POST"}
blocked_threats := {"honeytrap_access", "directory_traversal", "decoy_endpoint_access"}

allow if {
	input.method in allowed_methods
	not high_risk_request
}

high_risk_request if {
	input.risk_score > 7.0
}

high_risk_request if {
	input.threat_type in blocked_threats
}

high_risk_request if {
	input.threat_type == "lateral_movement"
	input.attack_path_score > 8.0
	input.confidence > 0.9
}
