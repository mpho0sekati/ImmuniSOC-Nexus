package com.immunisoc.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
public class TierController {

    @GetMapping(value = "/critical", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> critical() {
        return Map.of(
                "tier", "CRITICAL",
                "timestamp", Instant.now().toString(),
                "message", "Critical backend reached - enforced HSM/FIDO2 policies (simulated)"
        );
    }

    @GetMapping(value = "/standard", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> standard() {
        return Map.of(
                "tier", "STANDARD",
                "timestamp", Instant.now().toString(),
                "message", "Standard backend reached - cached OPA (simulated)"
        );
    }

    @GetMapping(value = "/public", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> publicTier() {
        return Map.of(
                "tier", "PUBLIC",
                "timestamp", Instant.now().toString(),
                "message", "Public backend reached - read-only replica (simulated)"
        );
    }
}
