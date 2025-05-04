package com.example.SecurityOAuth2.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Map;

@Component
public class OAuth2TokenValidatorUtil {

    public String isTokenValid(String token) {
        String issuer = getIssuerIdFromToken(token);
        JwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation(issuer);
        Jwt jwt=jwtDecoder.decode(token);
        if(jwt != null) {
            return (String) jwt.getClaims().get("sub");
        }
        return null;
    }

    private String getIssuerIdFromToken(String token) {
        try {
            String[] tokenParts = token.split("\\.");

            if (tokenParts.length < 2) {
                throw new IllegalArgumentException("Invalid token");
            }

            String payLoadJson = new String(Base64.getUrlDecoder().decode(tokenParts[1]));
            ObjectMapper mapper = new ObjectMapper();
            Map payloadMap = mapper.readValue(payLoadJson, Map.class);
            return (String) payloadMap.get("iss");
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
