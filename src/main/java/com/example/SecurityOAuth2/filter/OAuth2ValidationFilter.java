package com.example.SecurityOAuth2.filter;

import ch.qos.logback.core.util.StringUtil;
import com.example.SecurityOAuth2.util.OAuth2TokenValidatorUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class OAuth2ValidationFilter extends OncePerRequestFilter {

    private final OAuth2TokenValidatorUtil oAuth2TokenValidatorUtil;

    public OAuth2ValidationFilter(OAuth2TokenValidatorUtil oAuth2TokenValidatorUtil) {
        this.oAuth2TokenValidatorUtil = oAuth2TokenValidatorUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = null;
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            token = bearerToken.substring(7);
        }

        if (token != null) {

            String username = oAuth2TokenValidatorUtil.isTokenValid(token);
            if (StringUtil.isNullOrEmpty(username)) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired token");
                return;
            }

            // If you're not using roles
            List<GrantedAuthority> authorities = List.of();

            Authentication auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(request, response);
    }
}
