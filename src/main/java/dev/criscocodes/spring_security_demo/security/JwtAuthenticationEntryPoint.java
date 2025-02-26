package dev.criscocodes.spring_security_demo.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        System.out.println("JwtAuthenticationEntryPoint triggered! Invalid token detected.");

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");

        String message;
        if (Boolean.TRUE.equals(request.getAttribute("expired"))) {
            message = "Token has expired! Please log in again."; // Expired token detected
        } else if (Boolean.TRUE.equals(request.getAttribute("invalid_token"))) {
            message = "Invalid JWT token!";
        } else if (request.getHeader(HttpHeaders.AUTHORIZATION) == null && request.getRequestURI().contains("/api")) {
            message = "You need to log in!"; // No token provided
        } else if (authException.getMessage().toLowerCase().contains("invalid jwt signature")) {
            message = "Invalid JWT signature!";
        } else if (authException.getMessage().toLowerCase().contains("bad credentials")) {  // Detects incorrect login attempts
            message = "Invalid username or password!";
        } else {
            message = "Invalid or expired token!";
        }

        Map<String, Object> errorResponse = Map.of(
                "error", "Unauthorized",
                "message", message,
                "status", 401
        );

        response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
    }
}
