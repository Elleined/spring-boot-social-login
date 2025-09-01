package com.elleined.spring_boot_social_login.accesstoken;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

@Component
public class AccessTokenAuthenticationFilter extends OncePerRequestFilter {
    private final AccessTokenService accessTokenService;
    private final UserDetailsService userDetailsService;

    public AccessTokenAuthenticationFilter(AccessTokenService accessTokenService, UserDetailsService userDetailsService) {
        this.accessTokenService = accessTokenService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = Optional.ofNullable(request.getCookies()).stream()
                .flatMap(Arrays::stream)
                .filter(cookie -> "accessToken".equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);

        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            String username = accessTokenService.getUsername(token);
            if (username != null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                if (accessTokenService.isValid(token, userDetails)) {
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
