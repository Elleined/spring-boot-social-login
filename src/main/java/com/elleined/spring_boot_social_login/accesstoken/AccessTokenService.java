package com.elleined.spring_boot_social_login.accesstoken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

@Service
public class AccessTokenService {
    @Value("${access-token-secret-key}")
    private String accessTokenSecretKey;

    @Value("${access-token-expiration}")
    private Duration accessTokenExpiration;

    public boolean isValid(String token, UserDetails userDetails) {
        final String email = this.getUsername(token);
        return (email.equals(userDetails.getUsername()) && !this.isTokenExpired(token));
    }

    public String generateToken(String email) {
        Instant now = Instant.now();
        Instant expiry = now.plus(accessTokenExpiration);

        return Jwts.builder()
                .claims(new HashMap<>())
                .subject(email)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(this.getSignInKey())
                .compact();
    }

    public String getUsername(String token) {
        return this.getClaim(token, Claims::getSubject);
    }

    public Instant getExpiration(String token) {
        return this.getClaim(token, claims -> claims.getExpiration().toInstant());
    }

    private boolean isTokenExpired(String token) {
        return this.getExpiration(token).isBefore(Instant.now());
    }

    private Claims getAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private <T> T getClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = this.getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private SecretKey getSignInKey() {
        return Keys.hmacShaKeyFor(accessTokenSecretKey.getBytes(StandardCharsets.UTF_8));
    }
}
