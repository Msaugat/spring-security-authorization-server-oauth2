package com.sec.service;


import com.sec.datainit.ClientConfig;
import com.sec.dto.TokenResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class InternalOAuth2TokenService {

    private final AuthenticationManager authenticationManager;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<?> tokenGenerator;

    @Value("${app.security.issuer:http://localhost:9090}")
    private String issuerUrl;

    // PKCE challenge format: base64url, 43-128 chars
    private static final Pattern PKCE_CHALLENGE_PATTERN = Pattern.compile("^[A-Za-z0-9\\-_]{43,128}$");

    /**
     * Hybrid authentication endpoint supporting both direct token issuance and PKCE flow.
     *
     * @param username User's username
     * @param password User's plain-text password
     * @param codeChallenge Optional PKCE code challenge (S256 method) - for future standard flow compatibility
     * @param scope Optional requested scopes (comma-separated)
     * @return TokenResponse with access/refresh tokens
     */
    public TokenResponse authenticateAndGenerateTokens(
            String username,
            String password,
            String codeChallenge,
            String scope) {

        log.debug("Authenticating user: {} with PKCE: {}", username, codeChallenge != null ? "yes" : "no");

        // 1. Authenticate user credentials
        Authentication userAuthentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        // 2. Get or create internal client
        RegisteredClient client = getOrCreateInternalClient();

        // 3. Parse scopes
        Set<String> authorizedScopes = parseScopes(scope, client.getScopes());

        // 4.  Build authorization with conditional attribute
        OAuth2Authorization.Builder authBuilder = OAuth2Authorization.withRegisteredClient(client)
                .id(UUID.randomUUID().toString())
                .principalName(userAuthentication.getName())
                .authorizationGrantType(ClientConfig.INTERNAL_LOGIN_GRANT)
                .authorizedScopes(authorizedScopes)
                .attribute(Authentication.class.getName(), userAuthentication)
                .attribute("internal_flow", true);

        //  Only add pkce_challenge if it's provided (non-null, non-empty)
        if (StringUtils.hasText(codeChallenge)) {
            authBuilder.attribute("pkce_challenge", codeChallenge);
        }

        OAuth2Authorization authorization = authBuilder.build();

        // 5. Generate authorization code with PKCE (if challenge provided)
        String authorizationCodeValue = null;
        if (StringUtils.hasText(codeChallenge)) {
            validatePkceChallenge(codeChallenge);
            authorizationCodeValue = generateAuthorizationCodeWithPkce(authorization, client, codeChallenge);
            log.debug("Generated authorization code with PKCE for user: {}", username);
        }

        // 6. Generate tokens
        OAuth2AccessToken accessToken = generateAccessToken(authorization, client, userAuthentication, authorizedScopes);
        OAuth2RefreshToken refreshToken = generateRefreshToken(authorization, client, userAuthentication, authorizedScopes);

        // 7. Save authorization
        OAuth2Authorization.Builder finalBuilder = OAuth2Authorization.from(authorization)
                .token(accessToken, metadata -> {})
                .refreshToken(refreshToken);

        if (authorizationCodeValue != null) {
            OAuth2AuthorizationCode authCode = new OAuth2AuthorizationCode(
                    authorizationCodeValue,
                    Instant.now(),
                    Instant.now().plus(Duration.ofMinutes(5))
            );
            finalBuilder.token(authCode, metadata -> {});
        }

        authorizationService.save(finalBuilder.build());
        log.info("Tokens issued for user: {} (scopes: {})", username, authorizedScopes);

        return buildTokenResponse(accessToken, refreshToken, userAuthentication, authorizedScopes, authorizationCodeValue);
    }

    /**
     * Refresh token with rotation: invalidate old token, issue new pair.
     */
    public TokenResponse refreshAccessToken(String refreshTokenValue) {
        log.debug("Refreshing token");

        OAuth2Authorization authorization = authorizationService.findByToken(
                refreshTokenValue, OAuth2TokenType.REFRESH_TOKEN);

        if (authorization == null || authorization.getRefreshToken() == null) {
            throwOAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Invalid refresh token");
        }

        OAuth2RefreshToken existingRefresh = authorization.getRefreshToken().getToken();
        if (existingRefresh.getExpiresAt() != null && Instant.now().isAfter(existingRefresh.getExpiresAt())) {
            throwOAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Refresh token expired");
        }

        RegisteredClient client = registeredClientRepository.findById(authorization.getRegisteredClientId());
        Authentication userAuthentication = authorization.getAttribute(Authentication.class.getName());

        if (client == null || userAuthentication == null) {
            throwOAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Authorization context not found");
        }

        authorizationService.remove(authorization);
        log.debug("Rotated refresh token for user: {}", userAuthentication.getName());

        OAuth2Authorization newAuthorization = OAuth2Authorization.withRegisteredClient(client)
                .id(UUID.randomUUID().toString())
                .principalName(userAuthentication.getName())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizedScopes(authorization.getAuthorizedScopes())
                .attribute(Authentication.class.getName(), userAuthentication)
                .build();

        OAuth2AccessToken newAccessToken = generateAccessToken(newAuthorization, client, userAuthentication, authorization.getAuthorizedScopes());
        OAuth2RefreshToken newRefreshToken = generateRefreshToken(newAuthorization, client, userAuthentication, authorization.getAuthorizedScopes());

        OAuth2Authorization finalAuth = OAuth2Authorization.from(newAuthorization)
                .token(newAccessToken, metadata -> {})
                .refreshToken(newRefreshToken)
                .build();
        authorizationService.save(finalAuth);

        log.info(" Refreshed tokens for user: {}", userAuthentication.getName());
        return buildTokenResponse(newAccessToken, newRefreshToken, userAuthentication, authorization.getAuthorizedScopes(), null);
    }

    // ==================== PRIVATE HELPERS ====================

    private RegisteredClient getOrCreateInternalClient() {
        RegisteredClient client = registeredClientRepository.findByClientId("internal-client");

        if (client != null) {
            // Auto-heal: Update client if missing required settings
            boolean needsUpdate = !client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)
                    || !client.getClientSettings().isRequireProofKey()
                    || client.getRedirectUris().isEmpty(); // Also check for empty redirect URIs

            if (needsUpdate) {
                log.warn("⚠️ internal-client missing required settings. Updating...");
                client = updateClientWithPkceSupport(client);
                registeredClientRepository.save(client);
            }
            return client;
        }

        // Create new client with VALID redirect URI (required for AUTHORIZATION_CODE grant)
        client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("internal-client")
                .clientName("Internal PKCE Client")
                .clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost") // Placeholder for internal flow
                .redirectUri("urn:ietf:wg:oauth:2.0:oob") // Optional: for out-of-band flows
                .scope("read")
                .scope("write")
                .scope("openid")
                .scope("profile")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true) // PKCE required
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .reuseRefreshTokens(false) // Rotation enabled
                        .build())
                .build();

        registeredClientRepository.save(client);
        log.info("Created internal-client with PKCE support and redirect URIs");
        return client;
    }

    private RegisteredClient updateClientWithPkceSupport(RegisteredClient existing) {
        RegisteredClient.Builder builder = RegisteredClient.from(existing)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .reuseRefreshTokens(false)
                        .build());

        if (existing.getRedirectUris().isEmpty()) {
            builder.redirectUri("http://localhost");
            builder.redirectUri("urn:ietf:wg:oauth:2.0:oob");
        }

        return builder.build();
    }
    

    /**
     * Generate authorization code with PKCE challenge binding.
     * Stored for future compatibility with standard /oauth2/token endpoint.
     */
    private String generateAuthorizationCodeWithPkce(
            OAuth2Authorization authorization,
            RegisteredClient client,
            String codeChallenge) {

        // Generate cryptographically secure authorization code
        String codeValue = UUID.randomUUID().toString() + UUID.randomUUID().toString().replace("-", "");

        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                codeValue,
                Instant.now(),
                Instant.now().plus(Duration.ofMinutes(5)) // Short-lived for security
        );

        //  Store PKCE metadata for future standard flow compatibility
        OAuth2Authorization updated = OAuth2Authorization.from(authorization)
                .token(authorizationCode, metadata -> {
                    metadata.put(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
                    metadata.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
                    metadata.put("created_at", Instant.now());
                    metadata.put("internal_flow", true);
                })
                .build();

        authorizationService.save(updated);
        return codeValue;
    }
    

    private OAuth2AccessToken generateAccessToken(
            OAuth2Authorization authorization,
            RegisteredClient client,
            Authentication principal,
            Set<String> authorizedScopes) {

        log.debug("🔍 Generating access token: clientId={}, grantType={}, scopes={}",
                client.getClientId(),
                ClientConfig.INTERNAL_LOGIN_GRANT.getValue(),
                authorizedScopes);

        OAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .principal(principal)
                .authorization(authorization)
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(ClientConfig.INTERNAL_LOGIN_GRANT)
                .build();

        OAuth2Token generated = tokenGenerator.generate(context);

        if (generated == null) {
            log.error(" tokenGenerator.generate() returned null");
            throwOAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Failed to generate access token");
        }

        //  Handle both OAuth2AccessToken (expected) and raw Jwt (fallback)
        if (generated instanceof OAuth2AccessToken accessToken) {
            log.debug(" Access token generated (wrapped)");
            return accessToken;
        }
        else if (generated instanceof Jwt jwt) {
            // Fallback: Manually wrap Jwt into OAuth2AccessToken
            log.debug("️Got raw Jwt, wrapping into OAuth2AccessToken");

            Instant issuedAt = jwt.getIssuedAt() != null ? jwt.getIssuedAt() : Instant.now();
            Instant expiresAt = jwt.getExpiresAt() != null ? jwt.getExpiresAt() : issuedAt.plus(Duration.ofMinutes(30));

            return new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    jwt.getTokenValue(),
                    issuedAt,
                    expiresAt,
                    authorizedScopes //  Scopes are critical for resource server validation
            );
        }
        else {
            log.error("Unexpected token type: {}", generated.getClass());
            throwOAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Unexpected token type: " + generated.getClass());
        }
        throw new IllegalStateException("Unreachable code: token generation failed unexpectedly");
    }

    private OAuth2RefreshToken generateRefreshToken(
            OAuth2Authorization authorization,
            RegisteredClient client,
            Authentication principal,
            Set<String> authorizedScopes) {

        if (!client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            return null;
        }

        OAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .principal(principal)
                .authorization(authorization)
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();

        OAuth2Token generated = tokenGenerator.generate(context);

        if (generated == null) {
            log.warn("Refresh token generation returned null (optional)");
            return null;
        }

        if (generated instanceof OAuth2RefreshToken refreshToken) {
            return refreshToken;
        }

        log.warn("Unexpected refresh token type: {}", generated.getClass());
        return null;
    }

    private Set<String> parseScopes(String requested, Set<String> registered) {
        if (!StringUtils.hasText(requested)) {
            return new HashSet<>(registered); // Default to all registered scopes
        }

        Set<String> result = new HashSet<>();
        for (String scope : StringUtils.commaDelimitedListToSet(requested)) {
            if (registered.contains(scope)) {
                result.add(scope);
            } else {
                log.warn("⚠️ Requested scope '{}' not allowed for client '{}'", scope, registered);
            }
        }
        return result.isEmpty() ? new HashSet<>(registered) : result;
    }

    private void validatePkceChallenge(String codeChallenge) {
        if (!PKCE_CHALLENGE_PATTERN.matcher(codeChallenge).matches()) {
            throw new IllegalArgumentException(
                    "Invalid code_challenge format. Must be 43-128 base64url characters (A-Z, a-z, 0-9, -, _)"
            );
        }
    }

    private TokenResponse buildTokenResponse(
            OAuth2AccessToken accessToken,
            OAuth2RefreshToken refreshToken,
            Authentication principal,
            Set<String> scopes,
            String authorizationCode) {

        long expiresIn = (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null)
                ? ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt())
                : 1800;

        return new TokenResponse(
                accessToken.getTokenValue(),
                refreshToken != null ? refreshToken.getTokenValue() : null,
                "Bearer",
                expiresIn,
                String.join(" ", scopes),
                principal.getName(),
                authorizationCode // Optional: return code if client wants to complete standard flow later
        );
    }

    private void throwOAuth2Error(String errorCode, String description) {
        log.warn("OAuth2 error: {} - {}", errorCode, description);
        throw new OAuth2AuthenticationException(
                new OAuth2Error(errorCode, description, null)
        );
    }
}