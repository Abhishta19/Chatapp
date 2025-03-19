package com.example.chatapp.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.Claims;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Component;
import java.util.Date;

@Component
public class JwtUtil {
    private static final String SECRET_KEY = "h2DkL8xZ5Y3jG4pQo7TzF9s6VcXpM0rBdRfNhUeKw=="; // Base64-encoded key
    private static final long EXPIRATION_TIME = 86400000; // 24 hours

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String username) {
        return Jwts.builder()
                .subject(username)  // ✅ Replaces setSubject()
                .issuedAt(new Date()) // ✅ Replaces setIssuedAt()
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // ✅ Replaces setExpiration()
                .signWith(getSigningKey()) // ✅ No deprecated method
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    public boolean isTokenExpired(String token) {
        return extractClaims(token).getExpiration().before(new Date());
    }

    public boolean validateToken(String token, String username) {
        return extractUsername(token).equals(username) && !isTokenExpired(token);
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()  
                .verifyWith(getSigningKey()) // ✅ Correct method in JJWT 0.12+
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
