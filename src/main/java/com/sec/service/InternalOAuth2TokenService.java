package com.sec.service;


import com.sec.dto.TokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class InternalOAuth2TokenService {

    private final AuthenticationManager authenticationManager;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<?> tokenGenerator;

    // FIX #1: Remove @Autowired for AuthorizationServerContext - NOT a bean
    // Use AuthorizationServerContextHolder.getContext() at runtime

    public TokenResponse authenticateAndGenerateTokens(String username, String password) {
        // Step 1: Authenticate user credentials
        Authentication userAuthentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        // Step 2: Get or create the internal client
        RegisteredClient client = getOrCreateInternalClient();

        // FIX #2: Get AuthorizationServerContext from Holder at runtime
        AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();

        // Step 3: Set authorization server context (REQUIRED)
        AuthorizationServerContextHolder.setContext(authorizationServerContext);

        // ========================================
        // FIX #3: Use OAuth2Authorization.withRegisteredClient(client)
        // Official API from Spring docs [^33^]
        // ========================================
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(client)
                .id(UUID.randomUUID().toString())
                .principalName(userAuthentication.getName())
                .authorizationGrantType(new AuthorizationGrantType("custom_password"))
                .authorizedScopes(client.getScopes())
                .attribute(Authentication.class.getName(), userAuthentication)
                .attribute(OAuth2ParameterNames.USERNAME, username);

        // Build initial authorization for token context
        OAuth2Authorization initialAuthorization = authorizationBuilder.build();

        // Step 4: Generate Access Token
        // FIX #4: Use 'authorizationGrantType()' not 'grantType()'
        OAuth2TokenContext accessTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .principal(userAuthentication)
                .authorizationServerContext(authorizationServerContext)
                .authorization(initialAuthorization)
                .authorizedScopes(client.getScopes())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(new AuthorizationGrantType("custom_password"))
                .build();

        @SuppressWarnings("unchecked")
        OAuth2TokenGenerator<OAuth2AccessToken> accessTokenGenerator =
                (OAuth2TokenGenerator<OAuth2AccessToken>) tokenGenerator;
        OAuth2AccessToken accessToken = accessTokenGenerator.generate(accessTokenContext);

        if (accessToken == null) {
            throw new RuntimeException("Failed to generate access token");
        }

        // Create new builder from the initial authorization and add access token
        OAuth2Authorization.Builder mutableBuilder = OAuth2Authorization.from(initialAuthorization)
                .accessToken(accessToken);

        // Step 5: Generate Refresh Token
        // Use the authorization with access token for context
        OAuth2Authorization authorizationWithAccessToken = mutableBuilder.build();

        // FIX: Use 'authorizationGrantType()' not 'grantType()'
        OAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .principal(userAuthentication)
                .authorizationServerContext(authorizationServerContext)
                .authorization(authorizationWithAccessToken)
                .authorizedScopes(client.getScopes())
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizationGrantType(new AuthorizationGrantType("custom_password"))
                .build();

        @SuppressWarnings("unchecked")
        OAuth2TokenGenerator<OAuth2RefreshToken> refreshTokenGenerator =
                (OAuth2TokenGenerator<OAuth2RefreshToken>) tokenGenerator;
        OAuth2RefreshToken refreshToken = refreshTokenGenerator.generate(refreshTokenContext);

        if (refreshToken != null) {
            mutableBuilder.refreshToken(refreshToken);
        }

        // Step 6: Save authorization to database
        OAuth2Authorization finalAuthorization = mutableBuilder.build();
        authorizationService.save(finalAuthorization);

        // Step 7: Build response
        return TokenResponse.builder()
                .accessToken(accessToken.getTokenValue())
                .refreshToken(refreshToken != null ? refreshToken.getTokenValue() : null)
                .tokenType(accessToken.getTokenType().getValue())
                .expiresIn(accessToken.getExpiresAt() != null ?
                        ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()) : 1800)
                .issuedAt(accessToken.getIssuedAt())
                .expiresAt(accessToken.getExpiresAt())
                .scope(client.getScopes().stream().collect(Collectors.joining(" ")))
                .username(userAuthentication.getName())
                .build();
    }

    public TokenResponse refreshAccessToken(String refreshTokenValue) {
        // Find authorization by refresh token
        OAuth2Authorization authorization = authorizationService.findByToken(
                refreshTokenValue,
                OAuth2TokenType.REFRESH_TOKEN
        );

        if (authorization == null || authorization.getRefreshToken() == null) {
            throw new RuntimeException("Invalid refresh token");
        }

        OAuth2RefreshToken existingRefreshToken = authorization.getRefreshToken().getToken();

        // Check expiration
        if (existingRefreshToken.getExpiresAt() != null &&
                Instant.now().isAfter(existingRefreshToken.getExpiresAt())) {
            throw new RuntimeException("Refresh token expired");
        }

        RegisteredClient client = registeredClientRepository.findById(authorization.getRegisteredClientId());
        Authentication userAuthentication = authorization.getAttribute(Authentication.class.getName());

        // FIX: Get context from Holder
        AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();

        // Set context
        AuthorizationServerContextHolder.setContext(authorizationServerContext);

        // Revoke old refresh token
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
                .token(existingRefreshToken, metadata -> metadata.putAll(java.util.Collections.singletonMap("revoked", true)));

        OAuth2Authorization authorizationWithRevoked = authorizationBuilder.build();

        // Generate new access token
        // FIX: Use 'authorizationGrantType()' not 'grantType()'
        OAuth2TokenContext accessTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .principal(userAuthentication)
                .authorizationServerContext(authorizationServerContext)
                .authorization(authorizationWithRevoked)
                .authorizedScopes(authorization.getAuthorizedScopes())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();

        @SuppressWarnings("unchecked")
        OAuth2TokenGenerator<OAuth2AccessToken> accessTokenGenerator =
                (OAuth2TokenGenerator<OAuth2AccessToken>) tokenGenerator;
        OAuth2AccessToken newAccessToken = accessTokenGenerator.generate(accessTokenContext);

        if (newAccessToken == null) {
            throw new RuntimeException("Failed to generate access token");
        }

        authorizationBuilder.accessToken(newAccessToken);

        // Generate new refresh token (rotation)
        OAuth2Authorization authorizationWithNewAccess = authorizationBuilder.build();

        // FIX: Use 'authorizationGrantType()' not 'grantType()'
        OAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .principal(userAuthentication)
                .authorizationServerContext(authorizationServerContext)
                .authorization(authorizationWithNewAccess)
                .authorizedScopes(authorization.getAuthorizedScopes())
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();

        @SuppressWarnings("unchecked")
        OAuth2TokenGenerator<OAuth2RefreshToken> refreshTokenGenerator =
                (OAuth2TokenGenerator<OAuth2RefreshToken>) tokenGenerator;
        OAuth2RefreshToken newRefreshToken = refreshTokenGenerator.generate(refreshTokenContext);

        if (newRefreshToken != null) {
            authorizationBuilder.refreshToken(newRefreshToken);
        }

        // Save updated authorization
        OAuth2Authorization updatedAuthorization = authorizationBuilder.build();
        authorizationService.save(updatedAuthorization);

        return TokenResponse.builder()
                .accessToken(newAccessToken.getTokenValue())
                .refreshToken(newRefreshToken != null ? newRefreshToken.getTokenValue() : null)
                .tokenType(newAccessToken.getTokenType().getValue())
                .expiresIn(newAccessToken.getExpiresAt() != null ?
                        ChronoUnit.SECONDS.between(newAccessToken.getIssuedAt(), newAccessToken.getExpiresAt()) : 1800)
                .issuedAt(newAccessToken.getIssuedAt())
                .expiresAt(newAccessToken.getExpiresAt())
                .scope(authorization.getAuthorizedScopes().stream().collect(Collectors.joining(" ")))
                .username(userAuthentication.getName())
                .build();
    }

    private RegisteredClient getOrCreateInternalClient() {
        RegisteredClient client = registeredClientRepository.findByClientId("internal-client");

        if (client != null) {
            return client;
        }

        RegisteredClient internalClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("internal-client")
                .clientName("Internal Application Client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(new AuthorizationGrantType("custom_password"))
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("read")
                .scope("write")
                .scope("openid")
                .scope("profile")
                .clientSettings(org.springframework.security.oauth2.server.authorization.settings.ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(false)
                        .build())
                .tokenSettings(org.springframework.security.oauth2.server.authorization.settings.TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .reuseRefreshTokens(false)
                        .build())
                .build();

        registeredClientRepository.save(internalClient);
        return internalClient;
    }
}