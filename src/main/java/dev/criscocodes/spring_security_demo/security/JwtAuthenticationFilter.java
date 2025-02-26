package dev.criscocodes.spring_security_demo.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.sound.midi.Soundbank;
import java.io.IOException;
import java.util.Map;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        try {

            // Step 1: Extract JWT token from Authorization Header
            String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                filterChain.doFilter(request, response);
                return; // If no auth header data, continue request without authentication
            }

            String token = authHeader.substring(7);
            System.out.println("JWT Token Extracted: " + token);


            try {
                String username = jwtUtil.extractUsername(token);
                System.out.println("Extracted Username from Token: " + username);

                // Step 2: Validate Token & Set Authentication
                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    System.out.println("UserDetails Loaded: " + userDetails.getUsername());
                    System.out.println("User Roles: " + userDetails.getAuthorities());

                    if (jwtUtil.validateToken(token, username)) {
                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                        // Set authentication in Spring Security context to make user authenticated.
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        System.out.println("Authentication set for user: " + username);
                    }
                }

                // Step 3: Continue request processing
                filterChain.doFilter(request, response);

            } catch (io.jsonwebtoken.ExpiredJwtException e) {
                System.out.println(" Expired JWT Detected!");
                request.setAttribute("expired", true);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                request.getRequestDispatcher("/error").forward(request, response); // Ensures JSON response is sent

            } catch (io.jsonwebtoken.security.SecurityException | io.jsonwebtoken.MalformedJwtException e) {
                System.out.println("Invalid JWT Signature Detected!");
                request.setAttribute("invalid_token", true);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                request.getRequestDispatcher("/error").forward(request, response);

            }

        } catch (Exception e) {
            System.out.println("Unexpected JWT Authentication Error: " + e.getMessage());
            request.setAttribute("invalid_token", true);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            request.getRequestDispatcher("/error").forward(request, response);

        }
    }
}

