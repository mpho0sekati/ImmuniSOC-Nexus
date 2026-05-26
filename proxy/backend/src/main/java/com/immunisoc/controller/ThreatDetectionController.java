package com.immunisoc.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/threat-detection")
public class ThreatDetectionController {

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

    @GetMapping("/check-threats")
    public ResponseEntity<String> checkThreats(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        String queryString = request.getQueryString();
        String requestUri = request.getRequestURI();

        // Check for canary tokens in various request elements
        if (hasCanaryToken(userAgent) || hasCanaryToken(queryString) || hasCanaryToken(requestUri)) {
            logForensicEvent("Canary token detected", request);
            return ResponseEntity.status(451).body("Unavailable For Legal Reasons - Threat Detected");
        }

        // Check for directory traversal attempts
        if (hasDirectoryTraversal(queryString) || hasDirectoryTraversal(requestUri)) {
            logForensicEvent("Directory traversal detected", request);
            return ResponseEntity.status(451).body("Unavailable For Legal Reasons - Threat Detected");
        }

        return ResponseEntity.ok("No threats detected");
    }

    private boolean hasCanaryToken(String input) {
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

    private boolean hasDirectoryTraversal(String input) {
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