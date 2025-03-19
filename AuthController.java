package com.example.chatapp.controller;

import com.example.chatapp.service.AuthService;
import com.example.chatapp.util.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")  // Changed to match SecurityConfig path
public class AuthController {
    private final AuthService authService;
    private final JwtUtil jwtUtil;

    public AuthController(AuthService authService, JwtUtil jwtUtil) {
        this.authService = authService;
        this.jwtUtil = jwtUtil;
    }

    // Register User with JSON payload
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");
        
        String message = authService.registerUser(username, password);
        return ResponseEntity.ok(Map.of("message", message));
    }

    // User Login with JSON payload
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");
        
        String token = authService.authenticateUser(username, password);
        return ResponseEntity.ok(Map.of("token", token));
    }
}