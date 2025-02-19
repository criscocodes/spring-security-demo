package dev.criscocodes.spring_security_demo.controller;

import dev.criscocodes.spring_security_demo.model.User;
import dev.criscocodes.spring_security_demo.repository.UserRepository;
import dev.criscocodes.spring_security_demo.security.JwtUtil;
import dev.criscocodes.spring_security_demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserService userService;

    @Autowired
    private UserDetailsService userDetailsService;

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        try {
            User newUser = userService.registerUser(username, password);

            return ResponseEntity.status(201).body(Map.of(
                    "status", "success",
                    "message", "User registered successfully",
                    "username", newUser.getUsername()
            ));
        } catch (IllegalArgumentException e) {

            return ResponseEntity.status(400).body(Map.of(
                    "status", "error",
                    "message", e.getMessage()
            ));
        }
    }

    // Login User
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        try {
            // Step 1: Trigger Spring Security authentication
            // - Validates the username & password against our db,
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            // Step 2: Extract authenticated user data
            // - authentication.getPrincipal() returns an instance of UserDetails, our CustomUserDetails class.
            // - We cast it to UserDetails to retrieve the username.
            String loggedInUsername = ((UserDetails) authentication.getPrincipal()).getUsername();

            // Step 3: Retrieve the user’s roles permissions
            // - Gets roles as a List of Strings
            List<String> roles = authentication.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            // STep 4: Generate JWT token for the authenticated user
            String token = jwtUtil.generateToken(loggedInUsername);

            return ResponseEntity.ok()
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .body(Map.of(
                    "status", "success",
                    "message", "User logged in successfully!",
                    "username", loggedInUsername,
                    "roles", roles
//                    "token", token
            ));
        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of(
                    "status", "error",
                    "message", "Invalid username or password"
            ));
        }
    }
}
