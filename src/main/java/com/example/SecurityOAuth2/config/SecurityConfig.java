package com.example.SecurityOAuth2.config;

import com.example.SecurityOAuth2.filter.CustomOAuth2SuccessHandler;
import com.example.SecurityOAuth2.filter.OAuth2ValidationFilter;
import com.example.SecurityOAuth2.util.OAuth2TokenValidatorUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final OAuth2TokenValidatorUtil oAuth2TokenValidatorUtil;

    public SecurityConfig(OAuth2TokenValidatorUtil oAuth2TokenValidatorUtil) {
        this.oAuth2TokenValidatorUtil = oAuth2TokenValidatorUtil;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, CustomOAuth2SuccessHandler customOAuth2SuccessHandler) throws Exception {
        http.authorizeHttpRequests(auth ->
                        auth.anyRequest().authenticated())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2Login(oAuth ->
                        oAuth.successHandler(customOAuth2SuccessHandler))
                .addFilterBefore(new OAuth2ValidationFilter(oAuth2TokenValidatorUtil), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
