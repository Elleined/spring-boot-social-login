package com.elleined.spring_boot_social_login.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.time.Duration;

@Configuration
public class CORSConfig implements WebMvcConfigurer {

    private final String[] allowedOrigins;
    private final Duration corsMaxAge;

    public CORSConfig(@Value("#{'${allowed-origins}'.split(',')}") String[] allowedOrigins,
                      @Value("${cors-max-age}") Duration corsMaxAge) {
        this.allowedOrigins = allowedOrigins;
        this.corsMaxAge = corsMaxAge;
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins(allowedOrigins)
                .allowedMethods(HttpMethod.GET.name(), HttpMethod.POST.name())
                .maxAge(corsMaxAge.toSeconds());
    }
}
