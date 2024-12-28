package com.springsecurityoauth2.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class OAuth2LogoutSuccessHandler implements LogoutSuccessHandler {

   private final OAuth2AuthorizedClientService authorizedClientService;

    public OAuth2LogoutSuccessHandler(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (authentication != null) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;

            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                    oauthToken.getAuthorizedClientRegistrationId(),
                    oauthToken.getName()
            );

            if (authorizedClient != null) {
                String accessToken = authorizedClient.getAccessToken().getTokenValue();

                revokeAccessToken(accessToken);

                this.authorizedClientService.removeAuthorizedClient(oauthToken.getAuthorizedClientRegistrationId(), oauthToken.getName());
            }
        }

        response.sendRedirect("/login?logout");
    }

    private void revokeAccessToken(String accessToken) {
        String revokeUrl = "https://accounts.google.com/o/oauth2/revoke?token=" + accessToken;
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(revokeUrl).openConnection();
            connection.setRequestMethod("POST");
            connection.getResponseCode();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
