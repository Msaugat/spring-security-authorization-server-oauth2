package com.sec.datainit;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class ClientConfig {

    private final com.sec.service.JpaRegisteredClientRepository registeredClientRepository;

    @Bean
    public ApplicationRunner initializeClients() {
        return args -> {
            // Web client for standard OAuth 2.1 flow
            if (registeredClientRepository.findByClientId("web-client") == null) {

                RegisteredClient webClient = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("web-client")
                        .clientName("Web Application")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri("http://localhost:3000/callback")
                        .postLogoutRedirectUri("http://localhost:3000")
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .scope("read")
                        .scope("write")
                        .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(false)
                                .requireProofKey(true)
                                .build())
                        .tokenSettings(TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofMinutes(30))
                                .refreshTokenTimeToLive(Duration.ofDays(7))
                                .reuseRefreshTokens(false)
                                .build())
                        .build();

                registeredClientRepository.save(webClient);
            }

            // API client for machine-to-machine
            if (registeredClientRepository.findByClientId("api-client") == null) {

                RegisteredClient apiClient = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("api-client")
                        .clientName("API Client")
                        .clientSecret("{bcrypt}" + new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().encode("secret"))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .scope("read")
                        .scope("write")
                        .tokenSettings(TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofMinutes(60))
                                .build())
                        .build();

                registeredClientRepository.save(apiClient);
            }
        };
    }
}
