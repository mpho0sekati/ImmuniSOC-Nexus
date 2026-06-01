package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all configuration values for the ImmuniSOC-Nexus system
type Config struct {
	// Proxy configuration
	ProxyPort     int
	BackendURL    string
	ProxyTimeout  time.Duration
	MaxConnections int

	// Security configuration
	HandshakeSecretToken string
	SecurityAdminToken string
	JWTSecret          string
	EncryptionKey      string

	// OPA configuration
	OPAURL string

	// Logging configuration
	LogFilePath     string
	LogLevel        string
	LogMaxSize      int // MB
	LogMaxBackups   int
	LogMaxAge       int // days
	EnableAuditLog  bool

	// Rate limiting
	RateLimitRequests int
	RateLimitWindow   time.Duration

	// Deception configuration
	HoneytokenEnabled bool
	DeceptionEnabled  bool

	// Microsegmentation
	MicrosegEnabled bool

	// RBAC configuration
	RBACEnabled bool

	// Dashboard configuration
	DashboardRefreshInterval time.Duration
	DashboardRetryAttempts  int
	DashboardTimeout        time.Duration
}

// LoadConfig loads configuration from environment variables and .env file
func LoadConfig() (*Config, error) {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		// If .env file doesn't exist, continue with environment variables only
		// This is not an error condition since .env files are optional
	}

	cfg := &Config{
		// Default values
		ProxyPort:              getEnvAsInt("PROXY_PORT", 8080),
		BackendURL:             getEnv("BACKEND_URL", "http://localhost:8081"),
		ProxyTimeout:           getEnvAsDuration("PROXY_TIMEOUT", 30*time.Second),
		MaxConnections:         getEnvAsInt("MAX_CONNECTIONS", 1000),
		HandshakeSecretToken:   getEnv("HANDSHAKE_SECRET_TOKEN", ""),
		SecurityAdminToken:     getEnv("SECURITY_ADMIN_TOKEN", ""),
		JWTSecret:              getEnv("JWT_SECRET", ""),
		EncryptionKey:          getEnv("ENCRYPTION_KEY", ""),
		OPAURL:                 getEnv("OPA_URL", "http://localhost:8181"),
		LogFilePath:            getEnv("LOG_FILE_PATH", "./logs/security.log"),
		LogLevel:               getEnv("LOG_LEVEL", "info"),
		LogMaxSize:             getEnvAsInt("LOG_MAX_SIZE", 100),
		LogMaxBackups:          getEnvAsInt("LOG_MAX_BACKUPS", 3),
		LogMaxAge:              getEnvAsInt("LOG_MAX_AGE", 28),
		EnableAuditLog:         getEnvAsBool("ENABLE_AUDIT_LOG", true),
		RateLimitRequests:      getEnvAsInt("RATE_LIMIT_REQUESTS", 100),
		RateLimitWindow:        getEnvAsDuration("RATE_LIMIT_WINDOW", 1*time.Minute),
		HoneytokenEnabled:      getEnvAsBool("HONEYTOKEN_ENABLED", true),
		DeceptionEnabled:       getEnvAsBool("DECEPTION_ENABLED", true),
		MicrosegEnabled:        getEnvAsBool("MICROSEG_ENABLED", true),
		RBACEnabled:            getEnvAsBool("RBAC_ENABLED", true),
		DashboardRefreshInterval: getEnvAsDuration("DASHBOARD_REFRESH_INTERVAL", 30*time.Second),
		DashboardRetryAttempts:  getEnvAsInt("DASHBOARD_RETRY_ATTEMPTS", 3),
		DashboardTimeout:        getEnvAsDuration("DASHBOARD_TIMEOUT", 10*time.Second),
	}

	// Validate required security tokens
	if cfg.HandshakeSecretToken == "" {
		return nil, fmt.Errorf("HANDSHAKE_SECRET_TOKEN is required and must be at least 16 characters with mixed case, numbers, and special chars")
	}
	if len(cfg.HandshakeSecretToken) < 16 {
		return nil, fmt.Errorf("HANDSHAKE_SECRET_TOKEN must be at least 16 characters long")
	}
	
	if cfg.SecurityAdminToken == "" {
		return nil, fmt.Errorf("SECURITY_ADMIN_TOKEN is required and must be at least 16 characters with mixed case, numbers, and special chars")
	}
	if len(cfg.SecurityAdminToken) < 16 {
		return nil, fmt.Errorf("SECURITY_ADMIN_TOKEN must be at least 16 characters long")
	}

	return cfg, nil
}

// Helper functions to parse environment variables
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		switch value {
		case "true", "1", "yes", "on":
			return true
		case "false", "0", "no", "off":
			return false
		}
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.HandshakeSecretToken == "" {
		return fmt.Errorf("HandshakeSecretToken is required")
	}
	if c.SecurityAdminToken == "" {
		return fmt.Errorf("SecurityAdminToken is required")
	}
	if c.JWTSecret == "" {
		return fmt.Errorf("JWTSecret is required")
	}
	if c.EncryptionKey == "" {
		return fmt.Errorf("EncryptionKey is required")
	}

	// Validate security token strength
	if len(c.HandshakeSecretToken) < 16 {
		return fmt.Errorf("HandshakeSecretToken must be at least 16 characters")
	}
	if len(c.SecurityAdminToken) < 16 {
		return fmt.Errorf("SecurityAdminToken must be at least 16 characters")
	}
	if len(c.JWTSecret) < 16 {
		return fmt.Errorf("JWTSecret must be at least 16 characters")
	}
	if len(c.EncryptionKey) < 16 {
		return fmt.Errorf("EncryptionKey must be at least 16 characters")
	}

	// Check for complexity requirements
	if !hasComplexity(c.HandshakeSecretToken) {
		return fmt.Errorf("HandshakeSecretToken must contain uppercase, lowercase, digits, and special characters")
	}
	if !hasComplexity(c.SecurityAdminToken) {
		return fmt.Errorf("SecurityAdminToken must contain uppercase, lowercase, digits, and special characters")
	}
	if !hasComplexity(c.JWTSecret) {
		return fmt.Errorf("JWTSecret must contain uppercase, lowercase, digits, and special characters")
	}
	if !hasComplexity(c.EncryptionKey) {
		return fmt.Errorf("EncryptionKey must contain uppercase, lowercase, digits, and special characters")
	}

	return nil
}

// hasComplexity checks if a string has mixed case, digits, and special characters
func hasComplexity(s string) bool {
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	
	return hasUpper && hasLower && hasDigit && hasSpecial
}