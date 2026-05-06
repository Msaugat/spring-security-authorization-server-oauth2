package com.sec.datainit;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
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
@Slf4j
public class ClientConfig {

    private final com.sec.service.JpaRegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;

    //  Custom non-deprecated grant type for internal /api/auth/login flow
    public static final AuthorizationGrantType INTERNAL_LOGIN_GRANT =
            new AuthorizationGrantType("urn:custom:grant:internal-login");

    @Bean
    public ApplicationRunner initializeClients() {
        return args -> {
            log.info("🚀 Initializing OAuth2 clients...");

            // ========== 1. Web Client (Standard OAuth 2.1 Authorization Code + PKCE) ==========
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
                                .requireProofKey(true) //  PKCE required for public clients
                                .build())
                        .tokenSettings(TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofMinutes(30))
                                .refreshTokenTimeToLive(Duration.ofDays(7))
                                .reuseRefreshTokens(false)
                                .build())
                        .build();

                registeredClientRepository.save(webClient);
                log.info(" Created web-client");
            }

            // ========== 2. API Client (Machine-to-Machine / Client Credentials) ==========
            if (registeredClientRepository.findByClientId("api-client") == null) {
                String secret = passwordEncoder.encode("secret"); 

                RegisteredClient apiClient = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("api-client")
                        .clientName("API Client")
                        .clientSecret(secret) 
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .scope("read")
                        .scope("write")
                        .tokenSettings(TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofMinutes(60))
                                .build())
                        .build();

                registeredClientRepository.save(apiClient);
                log.info(" Created api-client (secret: 'secret')");
            }

            // ========== 3. INTERNAL CLIENT (For /api/auth/login - Hybrid Flow) ==========
            if (registeredClientRepository.findByClientId("internal-client") == null) {
                RegisteredClient internalClient = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("internal-client")
                        .clientName("Internal Application Client")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) 
                        .authorizationGrantType(INTERNAL_LOGIN_GRANT)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // For future standard flow
                        // REQUIRED: At least one redirect URI for AUTHORIZATION_CODE grant
                        .redirectUri("http://localhost")
                        .redirectUri("urn:ietf:wg:oauth:2.0:oob") // Optional: out-of-band
                        .scope("read")
                        .scope("write")
                        .scope("openid")
                        .scope("profile")
                        .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(false)
                                .requireProofKey(true) // PKCE ready for future
                                .build())
                        .tokenSettings(TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofMinutes(30))
                                .refreshTokenTimeToLive(Duration.ofDays(7))
                                .reuseRefreshTokens(false) //  Enable rotation
                                .build())
                        .build();

                registeredClientRepository.save(internalClient);
                log.info(" Created internal-client (for /api/auth/login)");
            }

            log.info("🎉 OAuth2 client initialization complete");
        };
    }
}
