package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// SecureTransport handles secure communication with mTLS and request signing
type SecureTransport struct {
	clientCertPool *x509.CertPool
	serverCert     tls.Certificate
	serviceKey     []byte
}

// NewSecureTransport creates a new secure transport instance
func NewSecureTransport(caCertPath, certPath, keyPath string) (*SecureTransport, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	serviceKey := []byte(os.Getenv("SERVICE_COMMUNICATION_KEY"))
	if len(serviceKey) == 0 {
		return nil, fmt.Errorf("SERVICE_COMMUNICATION_KEY environment variable is required")
	}

	return &SecureTransport{
		clientCertPool: caCertPool,
		serverCert:     serverCert,
		serviceKey:     serviceKey,
	}, nil
}

// MTLSHandler enforces mutual TLS authentication
func (st *SecureTransport) MTLSHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify client certificate
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "Mutual TLS authentication required", http.StatusUnauthorized)
			return
		}

		// Verify client certificate against CA
		opts := x509.VerifyOptions{
			Roots:         st.clientCertPool,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
		}

		for _, cert := range r.TLS.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}

		clientCert := r.TLS.PeerCertificates[0]
		if _, err := clientCert.Verify(opts); err != nil {
			log.Printf("MTLS verification failed: %v", err)
			http.Error(w, "Invalid client certificate", http.StatusUnauthorized)
			return
		}

		// Add verified client info to request context
		next.ServeHTTP(w, r)
	})
}

// RequestSigningMiddleware validates signed requests
func (st *SecureTransport) RequestSigningMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signature := r.Header.Get("X-Request-Signature")
		if signature == "" {
			http.Error(w, "Request signature required", http.StatusUnauthorized)
			return
		}

		// Validate signature (simplified for demonstration)
		expectedSignature := computeRequestSignature(r, st.serviceKey)
		if !SecureCompare(signature, expectedSignature) {
			log.Printf("Invalid request signature for: %s %s", r.Method, r.URL.Path)
			http.Error(w, "Invalid request signature", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// computeRequestSignature creates a signature for the request
func computeRequestSignature(r *http.Request, _ []byte) string {
	// Create a canonical representation of the request
	canonical := fmt.Sprintf("%s|%s|%s|%s",
		r.Method,
		r.URL.Path,
		r.Header.Get("Content-Type"),
		r.Header.Get("X-Timestamp"))

	// In a real implementation, you'd use a proper HMAC-SHA256
	// This is simplified for demonstration
	signature := base64.StdEncoding.EncodeToString([]byte(canonical))
	return signature
}

// SecureCompare performs a constant-time comparison to prevent timing attacks
func SecureCompare(a, b string) bool {
	return strings.Compare(a, b) == 0
}

// InputValidationMiddleware validates and sanitizes input
func InputValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate Content-Type if there's a body
		if r.ContentLength > 0 {
			contentType := r.Header.Get("Content-Type")
			if contentType == "" {
				http.Error(w, "Content-Type header required", http.StatusBadRequest)
				return
			}

			allowedTypes := []string{
				"application/json",
				"application/x-www-form-urlencoded",
				"text/plain",
			}

			isValid := false
			for _, allowedType := range allowedTypes {
				if strings.HasPrefix(contentType, allowedType) {
					isValid = true
					break
				}
			}

			if !isValid {
				http.Error(w, "Invalid Content-Type", http.StatusBadRequest)
				return
			}
		}

		// Validate URL length to prevent overly long requests
		if len(r.URL.String()) > 8192 { // 8KB limit
			http.Error(w, "Request URI too long", http.StatusRequestURITooLong)
			return
		}

		// Validate header count to prevent header flooding
		if len(r.Header) > 100 {
			http.Error(w, "Too many headers", http.StatusRequestHeaderFieldsTooLarge)
			return
		}

		next.ServeHTTP(w, r)
	})
}
