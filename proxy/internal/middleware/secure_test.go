package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInputValidationMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		url            string
		contentType    string
		body           string
		expectedStatus int
	}{
		{
			name:           "valid JSON request",
			method:         "POST",
			url:            "/test",
			contentType:    "application/json",
			body:           `{"test": "data"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid content type",
			method:         "POST",
			url:            "/test",
			contentType:    "application/xml",
			body:           `<test>data</test>`,
			expectedStatus: http.StatusBadRequest, // Now our implementation will reject invalid content types
		},
		{
			name:           "missing content type with body",
			method:         "POST",
			url:            "/test",
			contentType:    "",
			body:           `{"test": "data"}`,
			expectedStatus: http.StatusBadRequest, // Now our implementation will reject missing content type with body
		},
		{
			name:           "valid plain text",
			method:         "POST",
			url:            "/test",
			contentType:    "text/plain",
			body:           "test data",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "valid form data",
			method:         "POST",
			url:            "/test",
			contentType:    "application/x-www-form-urlencoded",
			body:           "field=value",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := InputValidationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}))

			var req *http.Request
			if tt.body != "" {
				req = httptest.NewRequest(tt.method, tt.url, bytes.NewBufferString(tt.body))
			} else {
				req = httptest.NewRequest(tt.method, tt.url, nil)
			}
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, tt.expectedStatus)
			}
		})
	}
}

func TestApplySecureHeaders(t *testing.T) {
	handler := ApplySecureHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Check that security headers are present
	headers := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"X-XSS-Protection":        "1; mode=block",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"Permissions-Policy":      "geolocation=(), microphone=(), camera=()",
	}

	for header, expectedValue := range headers {
		actualValue := rr.Header().Get(header)
		if actualValue != expectedValue {
			t.Errorf("expected header %s to be %s, got %s", header, expectedValue, actualValue)
		}
	}
}