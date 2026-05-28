package popia

import rego.v1

# Default deny - fail-closed security model
default allow = false

# Define allowed purposes for POPIA compliance
allowed_purposes = [
    "CUSTOMER_SERVICE",
    "IDENTITY_VERIFICATION",
    "FRAUD_PREVENTION",
    "LEGAL_COMPLIANCE",
    "CONSENTED_MARKETING"
]

# Data minimization rule - only allow access to essential fields based on purpose
essential_fields[fields] if {
    input.purpose == "CUSTOMER_SERVICE"
    fields := {"personal_id", "contact_info"}
}

essential_fields[fields] if {
    input.purpose == "IDENTITY_VERIFICATION"
    fields := {"personal_id", "identity_docs"}
}

essential_fields[fields] if {
    input.purpose == "FRAUD_PREVENTION"
    fields := {"transaction_history", "risk_indicators"}
}

essential_fields[fields] if {
    input.purpose == "LEGAL_COMPLIANCE"
    fields := {"audit_logs", "legal_docs"}
}

essential_fields[fields] if {
    input.purpose == "CONSENTED_MARKETING"
    fields := {"preferences", "contact_info"}
}

# Validate that only essential fields are accessed for the given purpose
data_minimization_compliant if {
    input.accessed_fields
    essential_fields(required_fields)
    every field in input.accessed_fields {
        field in required_fields
    }
}

valid_purpose if {
    input.purpose in allowed_purposes
}

allow if {
    valid_purpose
    data_minimization_compliant
    input.consent_given == true
    input.retention_period > 0
    input.retention_period <= 365  # Max retention period in days
}
