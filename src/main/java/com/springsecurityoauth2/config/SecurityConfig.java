package com.springsecurityoauth2.config;

import com.springsecurityoauth2.security.OAuth2LogoutSuccessHandler;
import com.springsecurityoauth2.service.OAuth2UserServiceImpl;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    private final OAuth2UserServiceImpl oAuth2UserService;

    private final OAuth2AuthorizedClientService authorizedClientService;

    public SecurityConfig(OAuth2UserServiceImpl oAuth2UserService, OAuth2AuthorizedClientService authorizedClientService) {
        this.oAuth2UserService = oAuth2UserService;
        this.authorizedClientService = authorizedClientService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/h2-console/*").permitAll()
                        .requestMatchers("/login", "/logout").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN") // Только для администраторов
                        .anyRequest().authenticated() // Все остальные запросы требуют аутентификации
                )
                .oauth2Login(oauth2Login -> oauth2Login
                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                                .userService(oAuth2UserService))
                        .failureHandler(authenticationFailureHandler())
                        .successHandler((request, response, authentication) -> {
                            logger.info("User '{}' successfully authenticated", authentication.getName());
                            response.sendRedirect("/user");
                        })
                )
                .logout(logout -> logout
                        .logoutUrl("/logout") // URL для выхода
                        .logoutSuccessHandler(logoutSuccessHandler()) // Обработчик для логаута
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                );
        return http.build();
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, exception) -> {
            if (exception instanceof OAuth2AuthenticationException) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "OAuth2 authentication failed");
            } else {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Authentication failed");
            }
        };
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new OAuth2LogoutSuccessHandler(authorizedClientService);
    }
}
