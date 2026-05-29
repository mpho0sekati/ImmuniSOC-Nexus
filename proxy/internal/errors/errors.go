package errors

import (
	"errors"
	"fmt"
)

// ErrorType represents different types of errors in the system
type ErrorType string

const (
	// Security-related errors
	ErrorTypeAuthentication ErrorType = "authentication_error"
	ErrorTypeAuthorization  ErrorType = "authorization_error"
	ErrorTypeValidation     ErrorType = "validation_error"
	
	// System-related errors
	ErrorTypeInternal     ErrorType = "internal_error"
	ErrorTypeNetwork      ErrorType = "network_error"
	ErrorTypeDatabase     ErrorType = "database_error"
	ErrorTypeConfiguration ErrorType = "configuration_error"
	
	// Security-specific errors
	ErrorTypeThreatDetected ErrorType = "threat_detected"
	ErrorTypeErrorLogging   ErrorType = "logging_error"
)

// SecurityError represents a security-related error with additional context
type SecurityError struct {
	Type       ErrorType
	Message    string
	Code       int
	Details    map[string]interface{}
	Cause      error
	Timestamp  string
	RequestID  string
	Severity   string // low, medium, high, critical
}

// Error returns the error message
func (e *SecurityError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap returns the underlying error
func (e *SecurityError) Unwrap() error {
	return e.Cause
}

// New creates a new SecurityError
func New(errType ErrorType, message string) *SecurityError {
	return &SecurityError{
		Type:      errType,
		Message:   message,
		Code:      getStatusCode(errType),
		Severity:  getSeverity(errType),
		Details:   make(map[string]interface{}),
	}
}

// NewWithCause creates a new SecurityError with an underlying cause
func NewWithCause(errType ErrorType, message string, cause error) *SecurityError {
	err := New(errType, message)
	err.Cause = cause
	return err
}

// NewWithDetails creates a new SecurityError with additional details
func NewWithDetails(errType ErrorType, message string, details map[string]interface{}) *SecurityError {
	err := New(errType, message)
	err.Details = details
	return err
}

// Wrap wraps an existing error with additional context
func Wrap(err error, errType ErrorType, message string) *SecurityError {
	if se, ok := err.(*SecurityError); ok {
		// If it's already a SecurityError, add to it
		se.Message = fmt.Sprintf("%s: %s", message, se.Message)
		return se
	}
	return NewWithCause(errType, message, err)
}

// IsSecurityError checks if an error is a SecurityError
func IsSecurityError(err error) bool {
	_, ok := err.(*SecurityError)
	return ok
}

// AsSecurityError tries to extract a SecurityError from an error chain
func AsSecurityError(err error) (*SecurityError, bool) {
	var se *SecurityError
	if errors.As(err, &se) {
		return se, true
	}
	return nil, false
}

// getStatusCode returns the appropriate HTTP status code for an error type
func getStatusCode(errType ErrorType) int {
	switch errType {
	case ErrorTypeAuthentication:
		return 401
	case ErrorTypeAuthorization:
		return 403
	case ErrorTypeValidation:
		return 400
	case ErrorTypeThreatDetected:
		return 400 // Bad request for detected threats
	default:
		return 500 // Internal server error
	}
}

// getSeverity returns the severity level for an error type
func getSeverity(errType ErrorType) string {
	switch errType {
	case ErrorTypeThreatDetected:
		return "critical"
	case ErrorTypeAuthentication, ErrorTypeAuthorization:
		return "high"
	case ErrorTypeValidation:
		return "medium"
	case ErrorTypeNetwork, ErrorTypeErrorLogging:
		return "medium"
	default:
		return "low"
	}
}

// AuthenticationError creates a new authentication error
func AuthenticationError(message string) *SecurityError {
	return New(ErrorTypeAuthentication, message)
}

// AuthorizationError creates a new authorization error
func AuthorizationError(message string) *SecurityError {
	return New(ErrorTypeAuthorization, message)
}

// ValidationError creates a new validation error
func ValidationError(message string) *SecurityError {
	return New(ErrorTypeValidation, message)
}

// InternalError creates a new internal error
func InternalError(message string) *SecurityError {
	return New(ErrorTypeInternal, message)
}

// ThreatDetectedError creates a new threat detected error
func ThreatDetectedError(message string) *SecurityError {
	return New(ErrorTypeThreatDetected, message)
}

// NetworkError creates a new network error
func NetworkError(message string) *SecurityError {
	return New(ErrorTypeNetwork, message)
}

// DatabaseError creates a new database error
func DatabaseError(message string) *SecurityError {
	return New(ErrorTypeDatabase, message)
}

// ConfigurationError creates a new configuration error
func ConfigurationError(message string) *SecurityError {
	return New(ErrorTypeConfiguration, message)
}

// ErrorWithRequestID adds a request ID to an error
func ErrorWithRequestID(err *SecurityError, requestID string) *SecurityError {
	err.RequestID = requestID
	return err
}

// ErrorWithDetail adds a detail to an error
func ErrorWithDetail(err *SecurityError, key string, value interface{}) *SecurityError {
	if err.Details == nil {
		err.Details = make(map[string]interface{})
	}
	err.Details[key] = value
	return err
}

// ErrorWithCode sets a custom error code
func ErrorWithCode(err *SecurityError, code int) *SecurityError {
	err.Code = code
	return err
}