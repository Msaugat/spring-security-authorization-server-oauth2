package com.sec.service;


import com.sec.dto.TokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class InternalOAuth2TokenService {

    private final AuthenticationManager authenticationManager;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<?> tokenGenerator;

    @Value("${app.security.issuer:http://localhost:9090}")
    private String issuerUrl;

    public TokenResponse authenticateAndGenerateTokens(String username, String password) {
        try {
            // Authenticate user
            Authentication userAuthentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            // Get or create internal client
            RegisteredClient client = getOrCreateInternalClient();

            // Build initial authorization
            OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                    .id(UUID.randomUUID().toString())
                    .principalName(userAuthentication.getName())
                    .authorizationGrantType(new AuthorizationGrantType("custom_password"))
                    .authorizedScopes(client.getScopes())
                    .attribute(Authentication.class.getName(), userAuthentication)
                    .attribute("username", username)
                    .build();

            OAuth2TokenContext accessTokenContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(client)
                    .principal(userAuthentication)
                    .authorization(authorization)
                    .authorizedScopes(client.getScopes())
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                    .authorizationGrantType(new AuthorizationGrantType("custom_password"))
                    .build();

            @SuppressWarnings("unchecked")
            OAuth2TokenGenerator<Jwt> jwtGenerator = (OAuth2TokenGenerator<Jwt>) tokenGenerator;
            Jwt accessToken = jwtGenerator.generate(accessTokenContext);

            if (accessToken == null) {
                throw new RuntimeException("Failed to generate access token");
            }

            // Build authorization with JWT token
            OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
                    .token(accessToken, metadata -> {});

            // Generate refresh token
            OAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(client)
                    .principal(userAuthentication)
                    .authorization(authorizationBuilder.build())
                    .authorizedScopes(client.getScopes())
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .authorizationGrantType(new AuthorizationGrantType("custom_password"))
                    .build();

            @SuppressWarnings("unchecked")
            OAuth2TokenGenerator<OAuth2RefreshToken> refreshTokenGenerator =
                    (OAuth2TokenGenerator<OAuth2RefreshToken>) tokenGenerator;
            OAuth2RefreshToken refreshToken = refreshTokenGenerator.generate(refreshTokenContext);

            if (refreshToken != null) {
                authorizationBuilder.refreshToken(refreshToken);
            }

            OAuth2Authorization finalAuth = OAuth2Authorization.from(authorization)
                    .token(accessToken, metadata -> {})
                    .refreshToken(refreshToken)
                    .build();
            authorizationService.save(finalAuth);


            return  buildTokenResponse(accessToken, refreshToken, userAuthentication, client.getScopes());

        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }



    public TokenResponse refreshAccessToken(String refreshTokenValue) {
        try {
            // Find existing authorization by refresh token
            OAuth2Authorization authorization = authorizationService.findByToken(
                    refreshTokenValue, OAuth2TokenType.REFRESH_TOKEN);

            if (authorization == null || authorization.getRefreshToken() == null) {
                throw new RuntimeException("Invalid refresh token");
            }

            OAuth2RefreshToken existingRefreshToken = authorization.getRefreshToken().getToken();

            if (existingRefreshToken.getExpiresAt() != null &&
                    Instant.now().isAfter(existingRefreshToken.getExpiresAt())) {
                throw new RuntimeException("Refresh token expired");
            }

            // Get client and user
            RegisteredClient client = registeredClientRepository.findById(authorization.getRegisteredClientId());
            Authentication userAuthentication = authorization.getAttribute(Authentication.class.getName());

            // Build new authorization context
            OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);

            // Generate new JWT access token
            OAuth2TokenContext accessTokenContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(client)
                    .principal(userAuthentication)
                    .authorization(authorization)
                    .authorizedScopes(authorization.getAuthorizedScopes())
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .build();

            @SuppressWarnings("unchecked")
            OAuth2TokenGenerator<Jwt> jwtGenerator = (OAuth2TokenGenerator<Jwt>) tokenGenerator;
            Jwt newAccessToken = jwtGenerator.generate(accessTokenContext);

            if (newAccessToken == null) {
                throw new RuntimeException("Failed to generate new access token");
            }

            authorizationBuilder.token(newAccessToken, metadata -> {});

            OAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(client)
                    .principal(userAuthentication)
                    .authorization(authorizationBuilder.build())
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
            OAuth2Authorization updatedAuth = OAuth2Authorization.from(authorization)
                    .token(newAccessToken, metadata -> {})
                    .refreshToken(newRefreshToken)
                    .build();
            authorizationService.save(updatedAuth);

            return buildTokenResponse(newAccessToken, newRefreshToken, userAuthentication, client.getScopes());

        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private RegisteredClient getOrCreateInternalClient() {
        RegisteredClient client = registeredClientRepository.findByClientId("internal-client");

        if (client != null) {
            return client;
        }

        RegisteredClient internalClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("internal-client")
                .clientName("Internal Application Client")
                .clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE)
                .authorizationGrantType(new AuthorizationGrantType("custom_password"))
                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN)
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

    public TokenResponse buildTokenResponse(
            Jwt accessToken,
            OAuth2RefreshToken refreshToken,
            Authentication principal,
            Set<String> scopes) {

        // Dynamically get issuer from JWT claim
        String issuer = accessToken.getClaimAsString("iss");

        return TokenResponse.builder()
                .accessToken(accessToken.getTokenValue())
                .refreshToken(refreshToken != null ? refreshToken.getTokenValue() : null)
                .tokenType("Bearer")
                .expiresIn(accessToken.getExpiresAt() != null ?
                        ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()) : 1800)
                .issuedAt(accessToken.getIssuedAt())
                .expiresAt(accessToken.getExpiresAt())
                .scope(String.join(" ", scopes))
                .username(principal.getName())
                .issuer(issuer)
                .build();
    }
}