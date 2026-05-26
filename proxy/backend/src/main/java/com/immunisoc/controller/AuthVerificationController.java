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

@RestController
@RequestMapping("/api")
public class AuthVerificationController {

    @Value("${auth.handshake.secret:default-secret}")
    private String handshakeSecret;

    private static final long TIMESTAMP_VALIDITY_WINDOW_SECONDS = 30;

    @RequestMapping(value = "/**", method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE})
    public ResponseEntity<String> handleRequest(@RequestHeader HttpHeaders headers, HttpServletRequest request) {
        try {
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

    private boolean verifyHmacSignature(HttpHeaders headers, HttpServletRequest request) throws Exception {
        String timestamp = headers.getFirst("X-Auth-Timestamp");
        String signature = headers.getFirst("X-Auth-Signature");

        if (timestamp == null || signature == null) {
            return false;
        }

        // Recreate the message that was signed
        String method = request.getMethod();
        String path = request.getRequestURI();
        String host = request.getServerName();

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
}