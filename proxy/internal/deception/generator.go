package deception

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// Honeytoken represents a deceptive credential/token used for detection
type Honeytoken struct {
	TokenID     string    `json:"token_id"`
	Value       string    `json:"value"`
	CreatedAt   time.Time `json:"created_at"`
	Description string    `json:"description"`
	Expiry      time.Time `json:"expiry"`
	AlertOnUse  bool      `json:"alert_on_use"`
}

// Generator handles honeytoken creation
type Generator struct {
	prefix string
}

// NewGenerator creates a new honeytoken generator
func NewGenerator(prefix string) *Generator {
	return &Generator{
		prefix: prefix,
	}
}

// GenerateHoneytoken creates a new honeytoken with specified parameters
func (g *Generator) GenerateHoneytoken(description string, expiryHours int) (*Honeytoken, error) {
	tokenID, err := g.generateRandomString(32) // Increased entropy
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	value, err := g.generateRandomString(64) // Increased entropy
	if err != nil {
		return nil, fmt.Errorf("failed to generate token value: %w", err)
	}

	now := time.Now()
	expiry := now.Add(time.Duration(expiryHours) * time.Hour)

	honeytoken := &Honeytoken{
		TokenID:     fmt.Sprintf("%s_%s", g.prefix, tokenID),
		Value:       fmt.Sprintf("%s_%s", g.prefix, value),
		CreatedAt:   now,
		Description: description,
		Expiry:      expiry,
		AlertOnUse:  true,
	}

	return honeytoken, nil
}

// GenerateFakePII creates fake personally identifiable information for canary records with increased entropy
func (g *Generator) GenerateFakePII() map[string]string {
	// Generate longer, more complex fake data
	idPart, _ := g.generateRandomString(16)
	emailPart, _ := g.generateRandomString(12)
	passportPart, _ := g.generateRandomString(10)
	
	return map[string]string{
		"fake_ssn":        fmt.Sprintf("%s-%s-%s", idPart[:3], idPart[4:6], idPart[6:10]),
		"fake_passport":   fmt.Sprintf("P%s%s", strings.ToUpper(passportPart[:4]), strings.ToUpper(passportPart[4:8])),
		"fake_email":      fmt.Sprintf("%s.%s@%s.honeypot.net", emailPart[:6], emailPart[6:], strings.ToLower(idPart[:8])),
		"fake_phone":      fmt.Sprintf("+%s-%s-%s", idPart[:3], idPart[3:6], idPart[6:10]),
		"fake_address":    fmt.Sprintf("%s Fake St, %s Ville, HV %s", idPart[:5], idPart[5:10], idPart[10:15]),
		"fake_employeeid": fmt.Sprintf("%s-%s", strings.ToUpper(idPart[:8]), strings.ToUpper(idPart[8:12])),
	}
}

// GenerateFakeCredentials creates fake credentials for canary records with increased entropy
func (g *Generator) GenerateFakeCredentials() map[string]string {
	username, _ := g.generateRandomString(16)  // Longer username
	password, _ := g.generateRandomString(32)  // Much longer password
	apiKey, _ := g.generateRandomString(48)    // Very long API key
	
	return map[string]string{
		"fake_username": fmt.Sprintf("honey_%s_%s", username[:8], username[8:16]),
		"fake_password": fmt.Sprintf("H0n3y_%s_%s!2026", password[:16], password[16:32]),
		"fake_api_key":  fmt.Sprintf("ak_honey_%s_%s_%s", apiKey[:16], apiKey[16:32], apiKey[32:48]),
		"fake_token":    fmt.Sprintf("ht_%s_%s", apiKey[:24], apiKey[24:48]),
		"fake_secret":   fmt.Sprintf("hs_%s_%s", password[:20], password[20:32]),
	}
}

// generateRandomString generates a cryptographically secure random string of specified length
func (g *Generator) generateRandomString(length int) (string, error) {
	// Use a larger byte array to ensure sufficient entropy
	bytes := make([]byte, length*2) // Generate more bytes than needed
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	
	// Use base64 encoding for better character distribution instead of hex
	encoded := base64.URLEncoding.EncodeToString(bytes)
	// Truncate to desired length, ensuring we have good entropy
	return encoded[:length], nil
}

// ValidateToken checks if a token is valid and not expired
func (g *Generator) ValidateToken(token *Honeytoken) bool {
	if token == nil {
		return false
	}
	
	now := time.Now()
	return now.Before(token.Expiry) && token.AlertOnUse
}

// GenerateDecoyEndpoints creates a list of decoy endpoints for deception
func (g *Generator) GenerateDecoyEndpoints() []string {
	return []string{
		"/admin/login",
		"/api/keys",
		"/api/admin/config",
		"/api/users/all",
		"/db/backup.sql",
		"/config/database.yml",
		"/etc/passwd",
		"/proc/self/environ",
		"/var/www/html/admin.php",
		"/backup/credentials.json",
		"/secrets/aws_keys.txt",
		"/internal/debug",
		"/debug/pprof/",
		"/metrics",
		"/actuator/shutdown",
		"/api/internal/status",
		"/admin/panel",
		"/api/admin/users",
		"/api/keys/all",
		"/config/secrets",
	}
}

// GenerateCanaryRecord creates a canary record with fake data
func (g *Generator) GenerateCanaryRecord(recordType string) map[string]interface{} {
	switch recordType {
	case "user":
		fakePII := g.GenerateFakePII()
		fakeCreds := g.GenerateFakeCredentials()
		return map[string]interface{}{
			"id":           fakePII["fake_employeeid"],
			"email":        fakePII["fake_email"],
			"full_name":    fmt.Sprintf("Honey %s", fakePII["fake_employeeid"]),
			"username":     fakeCreds["fake_username"],
			"password_hash": fmt.Sprintf("$2a$10$honey_%s", fakeCreds["fake_password"]),
			"api_key":      fakeCreds["fake_api_key"],
			"last_login":   time.Now().Format(time.RFC3339),
			"is_admin":     false,
			"department":   "Honeypot Security",
			"phone":        fakePII["fake_phone"],
		}
	case "credential":
		fakeCreds := g.GenerateFakeCredentials()
		return map[string]interface{}{
			"type":         "API_KEY",
			"key":          fakeCreds["fake_api_key"],
			"description":  "Development API Key - DO NOT USE IN PRODUCTION",
			"created_by":   "honeypot_system",
			"permissions":  []string{"read", "write"},
			"expires_at":   time.Now().AddDate(0, 0, 30).Format(time.RFC3339),
			"is_active":    true,
			"is_canary":    true,
		}
	case "database":
		fakePII := g.GenerateFakePII()
		return map[string]interface{}{
			"connection_string": fmt.Sprintf("mysql://honeypot:%s@honeypot-db.internal:3306/honeypot_users", fakePII["fake_passport"]),
			"username":          fakePII["fake_employeeid"],
			"password":          fakePII["fake_passport"],
			"database_name":     "honeypot_production",
			"host":              "honeypot-db.internal",
			"port":              3306,
			"is_canary":         true,
		}
	default:
		return map[string]interface{}{
			"type":    recordType,
			"data":    "canary_record",
			"status":  "active",
			"canary":  true,
			"created": time.Now().Unix(),
		}
	}
}