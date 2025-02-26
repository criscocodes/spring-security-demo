package dev.criscocodes.spring_security_demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class ProtectedController {

    // Accessible to any authenticated user
    @GetMapping("/protected")
    public Map<String, Object> getProtectedData(Authentication authentication) {
        return Map.of(
                "message", "This is a protected API endpoint!",
                "status", "success",
                "username", authentication.getName(),
                "roles", authentication.getAuthorities()
        );
    }

    // Only accessible to users with role ADMIN
    @GetMapping("/admin-only")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public Map<String, Object> getAdminData(Authentication authentication) {
        System.out.println("Accessing /api/admin-role with user: " + authentication.getName());
        System.out.println("User roles: " + authentication.getAuthorities());
        return Map.of(
                "message", "Welcome, Admin",
                "status", "success"
        );
    }
}
