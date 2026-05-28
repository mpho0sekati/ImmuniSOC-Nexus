package com.immunisoc.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Formatter;

import javax.servlet.http.HttpServletRequest;
import java.util.stream.Collectors;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api")
public class AuthVerificationController {

    @Value("${auth.handshake.secret}")
    private String handshakeSecret;

    private static final long TIMESTAMP_VALIDITY_WINDOW_SECONDS = 30;

    // Canary dataset flags and tripwire strings
    private static final List<String> CANARY_TOKENS = Arrays.asList(
        "canary-token-12345",
        "honeytoken-sensitive-data",
        "tripwire-access-token",
        "decoy-user-profile-abc",
        "canary-document-key-xyz"
    );

    // Directory traversal patterns to detect
    private static final List<String> TRAVERSAL_PATTERNS = Arrays.asList(
        "../",
        "..\\",
        "%2e%2e%2f",
        "%2e%2e%5c",
        "..%2f",
        "..%5c",
        "....//",
        "....\\\\"
    );

    @RequestMapping(value = "/**", method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE})
    public ResponseEntity<String> handleRequest(@RequestHeader HttpHeaders headers, HttpServletRequest request) {
        try {
            // Check for threats first
            if (hasCanaryToken(request) || hasDirectoryTraversal(request)) {
                logForensicEvent("Threat detected via canary token or directory traversal", request);
                return ResponseEntity.status(451).body("Unavailable For Legal Reasons - Threat Detected");
            }

            // Verify HMAC signature
            if (!verifyHmacSignature(headers, request)) {
                return ResponseEntity.status(401).body("Unauthorized: Invalid HMAC signature");
            }

            // Verify timestamp is within validity window
            if (!verifyTimestamp(headers)) {
                return ResponseEntity.status(401).body("Unauthorized: Timestamp outside validity window");
            }

            // Process the request
            return ResponseEntity.ok("Request processed successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error: " + e.getMessage());
        }
    }

    private boolean hasCanaryToken(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        String queryString = request.getQueryString();
        String requestUri = request.getRequestURI();
        String requestBody = getRequestPayload(request); // This would need to be implemented to read body
        
        return hasCanaryTokenInString(userAgent) || 
               hasCanaryTokenInString(queryString) || 
               hasCanaryTokenInString(requestUri) ||
               hasCanaryTokenInString(requestBody);
    }

    private boolean hasCanaryTokenInString(String input) {
        if (input == null) {
            return false;
        }

        String lowerInput = input.toLowerCase();
        for (String token : CANARY_TOKENS) {
            if (lowerInput.contains(token.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private boolean hasDirectoryTraversal(HttpServletRequest request) {
        String queryString = request.getQueryString();
        String requestUri = request.getRequestURI();
        String requestBody = getRequestPayload(request); // This would need to be implemented to read body
        
        return hasDirectoryTraversalInString(queryString) || 
               hasDirectoryTraversalInString(requestUri) ||
               hasDirectoryTraversalInString(requestBody);
    }

    private boolean hasDirectoryTraversalInString(String input) {
        if (input == null) {
            return false;
        }

        String lowerInput = input.toLowerCase();
        for (String pattern : TRAVERSAL_PATTERNS) {
            if (lowerInput.contains(pattern.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    // Helper method to get request payload (would need custom implementation)
    private String getRequestPayload(HttpServletRequest request) {
        try {
            return request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));
        } catch (Exception e) {
            // If we can't read the body, we return empty to avoid breaking the flow
            return "";
        }
    }

    private boolean verifyHmacSignature(HttpHeaders headers, HttpServletRequest request) throws Exception {
        String timestamp = headers.getFirst("X-Auth-Timestamp");
        String signature = headers.getFirst("X-Auth-Signature");

        if (timestamp == null || signature == null) {
            return false;
        }

        // Recreate the message that was signed
        String method = request.getMethod();
        String path = request.getRequestURI();
        String host = request.getHeader("Host");
        if (host == null || host.isEmpty()) {
            host = request.getServerName();
        }

        String message = method + "|" + path + "|" + timestamp + "|" + host;

        // Calculate expected signature
        String expectedSignature = calculateHmacSha256(message, handshakeSecret);

        // Use constant-time comparison to prevent timing attacks
        return MessageDigest.isEqual(signature.getBytes(StandardCharsets.UTF_8), 
                                   expectedSignature.getBytes(StandardCharsets.UTF_8));
    }

    private boolean verifyTimestamp(HttpHeaders headers) {
        String timestampStr = headers.getFirst("X-Auth-Timestamp");

        if (timestampStr == null) {
            return false;
        }

        try {
            long timestamp = Long.parseLong(timestampStr);
            long currentTime = Instant.now().getEpochSecond();
            long diff = Math.abs(currentTime - timestamp);

            return diff <= TIMESTAMP_VALIDITY_WINDOW_SECONDS;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private String calculateHmacSha256(String data, String key) throws Exception {
        Mac sha256Hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        sha256Hmac.init(secretKey);
        byte[] hash = sha256Hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));

        Formatter formatter = new Formatter();
        for (byte b : hash) {
            formatter.format("%02x", b);
        }
        String result = formatter.toString();
        formatter.close();

        return result;
    }

    private void logForensicEvent(String eventType, HttpServletRequest request) {
        // Append-only event logging for forensic ingestion
        String logEntry = String.format(
            "[FORENSIC_LOG] %s | %s | %s | %s | %s | %s",
            System.currentTimeMillis(),
            eventType,
            request.getRemoteAddr(),
            request.getRequestURI(),
            request.getQueryString(),
            request.getHeader("User-Agent")
        );
        
        // In a real implementation, this would write to an append-only log file or database
        System.out.println(logEntry); // For demonstration purposes
    }
}
