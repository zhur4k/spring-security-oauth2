package com.springsecurityoauth2.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Optional;

@Component
public class OAuth2LogoutSuccessHandler implements LogoutSuccessHandler {

    private final OAuth2AuthorizedClientService authorizedClientService;

    private final RestTemplate restTemplate;

    public OAuth2LogoutSuccessHandler(OAuth2AuthorizedClientService authorizedClientService, RestTemplate restTemplate) {
        this.authorizedClientService = authorizedClientService;
        this.restTemplate = restTemplate;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String username = authentication.getName();

        Optional<OAuth2AuthorizedClient> authorizedClient =
                Optional.ofNullable(authorizedClientService.loadAuthorizedClient("google", username));

        if (authorizedClient.isPresent()) {
            OAuth2AuthorizedClient client = authorizedClient.get();

            OAuth2AccessToken accessToken = client.getAccessToken();
            OAuth2RefreshToken refreshToken = client.getRefreshToken();

            if (accessToken != null) {
                revokeToken(accessToken.getTokenValue());
            }
            if (refreshToken != null) {
                revokeToken(refreshToken.getTokenValue());
            }

            authorizedClientService.removeAuthorizedClient("google", username);
        }

        response.sendRedirect("/login");
    }

    public void revokeToken(String token) {
        String revokeUrl = "https://oauth2.googleapis.com/revoke?token=" + token;

        try {
            // Отправка POST запроса с параметром token
            ResponseEntity<String> response = restTemplate.postForEntity(revokeUrl, null, String.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                System.out.println("Token revoked successfully");
            } else {
                System.out.println("Failed to revoke token: " + response.getStatusCode());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}