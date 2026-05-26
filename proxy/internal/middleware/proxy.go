package middleware

import (
	"net/http"
	"strconv"
)

// ApplySecureHeaders injects security headers to enhance protection
func ApplySecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set X-Frame-Options to prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		
		// Set X-Content-Type-Options to prevent MIME-type sniffing attacks
		w.Header().Set("X-Content-Type-Options", "nosniff")
		
		// Set Strict-Transport-Security (HSTS) to enforce HTTPS
		maxAge := int64(31536000) // 1 year in seconds
		w.Header().Set("Strict-Transport-Security", "max-age="+strconv.FormatInt(maxAge, 10)+" ; includeSubDomains")
		
		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	})
}