package dev.criscocodes.spring_security_demo.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class ProtectedController {

    // Protected endpoint that requires authentication
    @GetMapping("/protected")
    public Map<String, Object> getProtectedData(Authentication authentication) {
        return Map.of(
                "message", "This is a protected API endpoint!",
                "status", "success",
                "username", authentication.getName(),
                "roles", authentication.getAuthorities()
        );
    }
}
