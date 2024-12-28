package com.springsecurityoauth2.config;

import com.springsecurityoauth2.security.CustomAuthenticationFailureHandler;
import com.springsecurityoauth2.security.OAuth2LogoutSuccessHandler;
import com.springsecurityoauth2.service.OAuth2UserServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final OAuth2UserServiceImpl oAuth2UserService;

    private final OAuth2AuthorizedClientService authorizedClientService;

    private final ClientRegistrationRepository clientRegistrationRepository;

    private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

    public SecurityConfig(OAuth2UserServiceImpl oAuth2UserService, OAuth2AuthorizedClientService authorizedClientService, ClientRegistrationRepository clientRegistrationRepository, CustomAuthenticationFailureHandler customAuthenticationFailureHandler) {
        this.oAuth2UserService = oAuth2UserService;
        this.authorizedClientService = authorizedClientService;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.customAuthenticationFailureHandler = customAuthenticationFailureHandler;
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
                        .defaultSuccessUrl("/user")
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
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new OAuth2LogoutSuccessHandler(authorizedClientService);
    }
}
