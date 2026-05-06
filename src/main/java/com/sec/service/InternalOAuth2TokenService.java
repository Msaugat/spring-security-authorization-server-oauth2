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

        // 1. Authenticate user credentials via Spring Security
        Authentication userAuthentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        // 2. Get or create internal client (configured for AUTHORIZATION_CODE + PKCE)
        RegisteredClient client = getOrCreateInternalClient();

        // 3. Parse and validate requested scopes
        Set<String> authorizedScopes = parseScopes(scope, client.getScopes());

        // 4. Build OAuth2Authorization with AUTHORIZATION_CODE grant (PKCE-compatible)
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .id(UUID.randomUUID().toString())
                .principalName(userAuthentication.getName())
                .authorizationGrantType(ClientConfig.INTERNAL_LOGIN_GRANT) //  Use custom grant
                .authorizedScopes(authorizedScopes)
                .attribute(Authentication.class.getName(), userAuthentication)
                .attribute("internal_flow", true)
                .attribute("pkce_challenge", codeChallenge) // Optional: for audit
                .build();

        // 5. If PKCE challenge provided, generate authorization code with challenge binding (for future use)
        String authorizationCodeValue = null;
        if (StringUtils.hasText(codeChallenge)) {
            validatePkceChallenge(codeChallenge);
            authorizationCodeValue = generateAuthorizationCodeWithPkce(authorization, client, codeChallenge);
            log.debug("Generated authorization code with PKCE for user: {}", username);
        }

        // 6. Generate ACCESS TOKEN (custom claims auto-injected via OAuth2TokenCustomizer bean)
        OAuth2AccessToken accessToken = generateAccessToken(authorization, client, userAuthentication, authorizedScopes);

        // 7. Generate REFRESH TOKEN (with rotation enabled)
        OAuth2RefreshToken refreshToken = generateRefreshToken(authorization, client, userAuthentication, authorizedScopes);

        // 8. Save final authorization with all tokens
        OAuth2Authorization.Builder authBuilder = OAuth2Authorization.from(authorization)
                .token(accessToken, metadata -> {})
                .refreshToken(refreshToken);

        // Optionally store authorization code for audit/traceability
        if (authorizationCodeValue != null) {
            OAuth2AuthorizationCode authCode = new OAuth2AuthorizationCode(
                    authorizationCodeValue,
                    Instant.now(),
                    Instant.now().plus(Duration.ofMinutes(5)) // Short-lived for security
            );
            authBuilder.token(authCode, metadata -> {});
        }

        authorizationService.save(authBuilder.build());
        log.info("✅ Tokens issued for user: {} (scopes: {})", username, authorizedScopes);

        // 9. Build and return response
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

        // 🔁 Token Rotation: Remove old authorization before issuing new tokens
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

        log.info("✅ Refreshed tokens for user: {}", userAuthentication.getName());
        return buildTokenResponse(newAccessToken, newRefreshToken, userAuthentication, authorization.getAuthorizedScopes(), null);
    }

    // ==================== PRIVATE HELPERS ====================

    private RegisteredClient getOrCreateInternalClient() {
        RegisteredClient client = registeredClientRepository.findByClientId("internal-client");

        if (client != null) {
            // Auto-heal: Update client if missing required settings
            boolean needsUpdate = !client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)
                    || !client.getClientSettings().isRequireProofKey()
                    || client.getRedirectUris().isEmpty(); // ✅ Also check for empty redirect URIs

            if (needsUpdate) {
                log.warn("⚠️ internal-client missing required settings. Updating...");
                client = updateClientWithPkceSupport(client);
                registeredClientRepository.save(client);
            }
            return client;
        }

        // ✅ Create new client with VALID redirect URI (required for AUTHORIZATION_CODE grant)
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
        log.info("✅ Created internal-client with PKCE support and redirect URIs");
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

    private OAuth2Authorization buildAuthorization(
            RegisteredClient client,
            Authentication principal,
            Set<String> authorizedScopes) {

        return OAuth2Authorization.withRegisteredClient(client)
                .id(UUID.randomUUID().toString())
                .principalName(principal.getName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(authorizedScopes)
                .attribute(Authentication.class.getName(), principal)
                .attribute("internal_flow", true) // Marker for audit logs
                .build();
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

        // ✅ Store PKCE metadata for future standard flow compatibility
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

        OAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .principal(principal)
                .authorization(authorization)
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(ClientConfig.INTERNAL_LOGIN_GRANT)
                .build();

        OAuth2Token generated = tokenGenerator.generate(context);
        if (generated == null || !(generated instanceof OAuth2AccessToken)) {
            log.error("❌ Failed to generate access token for user: {}", principal.getName());
            throwOAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Failed to generate access token");
        }
        return (OAuth2AccessToken) generated;
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
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // ✅ Standard for refresh
                .build();

        OAuth2Token generated = tokenGenerator.generate(context);
        return (generated instanceof OAuth2RefreshToken) ? (OAuth2RefreshToken) generated : null;
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