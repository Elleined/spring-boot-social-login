package com.elleined.spring_boot_social_login.config;

import com.elleined.spring_boot_social_login.accesstoken.AccessTokenAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private final String loginPage;
    private final String loginSuccess;
    private final String loginFailed;

    private final AccessTokenAuthenticationFilter accessTokenAuthenticationFilter;

    public SecurityConfiguration(String loginPage,
                                 String loginSuccess,
                                 String loginFailed,
                                 AccessTokenAuthenticationFilter accessTokenAuthenticationFilter) {

        this.loginPage = loginPage;
        this.loginSuccess = loginSuccess;
        this.loginFailed = loginFailed;
        this.accessTokenAuthenticationFilter = accessTokenAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Only use for JWT
                .addFilterBefore(accessTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class) // Only use for JWT
                .authorizeHttpRequests(request -> request
                        .requestMatchers(HttpMethod.POST, "/login/**", "/register/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(oc -> oc
                        .loginPage(loginPage)
                        .defaultSuccessUrl(loginSuccess, true)
                        .failureUrl(loginFailed)
                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint.userService()))
                .build();
    }
}
