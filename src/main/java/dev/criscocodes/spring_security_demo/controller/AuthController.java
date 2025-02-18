package dev.criscocodes.spring_security_demo.controller;

import dev.criscocodes.spring_security_demo.model.User;
import dev.criscocodes.spring_security_demo.repository.UserRepository;
import dev.criscocodes.spring_security_demo.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        // Check if user already exists
        if (userRepository.findByUsername(username).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "error",
                    "message", "User already exists!"
            ));
        }

        // Create and save new user
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password)); // Encrypt password
        user.setRoles(Collections.singleton("USER")); // Default role "USER"

        userRepository.save(user);

        return ResponseEntity.status(201).body(Map.of(
                "status", "success",
                "message", "User registered successfully!",
                "username", user.getUsername()
        ));

    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        try {
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            // TODO: REMOVE Logs
            System.out.println("Authentication Object: " + authentication);
            // Load user details
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            // Generate JWT token
            String token = jwtUtil.generateToken(userDetails.getUsername());

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "User logged in successfully!",
                    "username", username,
                    "token", token
            ));

        } catch(Exception e) {
            return ResponseEntity.status(401).body(Map.of(
               "status", "error",
               "message", "Invalid username or password"
            ));
        }
    }
}
