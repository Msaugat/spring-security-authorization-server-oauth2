package com.sec.security.jpa;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sec.entity.OAuth2AuthorizationConsentEntity;
import com.sec.entity.OAuth2AuthorizationEntity;
import com.sec.entity.RegisteredClientEntity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Utility class for converting between JPA entities and Spring Security OAuth2 objects.
 */

/**
 * Utility class for converting between JPA entities and Spring Security OAuth2 objects.
 * Handles Duration serialization/deserialization properly with Jackson JSR310.
 */
@Slf4j
public final class JpaConverters {

    /**
     * Configured ObjectMapper with JSR310 module for Duration support
     */
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule());

    // Converter for ClientAuthenticationMethod
    private static final Converter<String, ClientAuthenticationMethod> CLIENT_AUTH_METHOD_CONVERTER =
            source -> new ClientAuthenticationMethod(source);

    private JpaConverters() {}

    // ==================== JSON HELPERS ====================

    static String toJson(Object object) {
        try {
            return MAPPER.writeValueAsString(object);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    static <T> T fromJson(String json, TypeReference<T> typeReference) {
        if (!StringUtils.hasText(json)) {
            return null;
        }
        try {
            return MAPPER.readValue(json, typeReference);
        } catch (IOException e) {
            log.error("Failed to parse JSON: {}", json.substring(0, Math.min(json.length(), 100)), e);
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    static Set<String> parseSet(String json) {
        Set<String> result = fromJson(json, new TypeReference<Set<String>>() {});
        return result != null ? result : Collections.emptySet();
    }

    static Map<String, Object> parseMap(String json) {
        Map<String, Object> result = fromJson(json, new TypeReference<Map<String, Object>>() {});
        return result != null ? result : Collections.emptyMap();
    }

    // ==================== REGISTERED CLIENT ====================

    public static RegisteredClientEntity toEntity(RegisteredClient registeredClient) {
        List<String> clientAuthenticationMethods = registeredClient.getClientAuthenticationMethods().stream()
                .map(ClientAuthenticationMethod::getValue)
                .collect(Collectors.toList());

        List<String> authorizationGrantTypes = registeredClient.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue)
                .collect(Collectors.toList());

        return RegisteredClientEntity.builder()
                .id(registeredClient.getId())
                .clientId(registeredClient.getClientId())
                .clientSecret(registeredClient.getClientSecret())
                .clientName(registeredClient.getClientName())
                .clientAuthenticationMethods(toJson(clientAuthenticationMethods))
                .authorizationGrantTypes(toJson(authorizationGrantTypes))
                .redirectUris(toJson(new ArrayList<>(registeredClient.getRedirectUris())))
                .postLogoutRedirectUris(toJson(new ArrayList<>(registeredClient.getPostLogoutRedirectUris())))
                .scopes(toJson(new ArrayList<>(registeredClient.getScopes())))
                .clientSettings(toJson(registeredClient.getClientSettings().getSettings()))
                .tokenSettings(toJson(registeredClient.getTokenSettings().getSettings()))
                .build();
    }

    public static RegisteredClient toRegisteredClient(RegisteredClientEntity entity) {
        Set<String> clientAuthenticationMethods = parseSet(entity.getClientAuthenticationMethods());
        Set<String> authorizationGrantTypes = parseSet(entity.getAuthorizationGrantTypes());
        Set<String> redirectUris = parseSet(entity.getRedirectUris());
        Set<String> postLogoutRedirectUris = parseSet(entity.getPostLogoutRedirectUris());
        Set<String> scopes = parseSet(entity.getScopes());

        // Parse settings safely
        ClientSettings clientSettings = parseClientSettings(entity.getClientSettings());
        TokenSettings tokenSettings = parseTokenSettings(entity.getTokenSettings());

        log.debug("Building RegisteredClient:");
        log.debug("  - ID: {}", entity.getId());
        log.debug("  - ClientID: {}", entity.getClientId());
        log.debug("  - Access Token TTL: {} seconds",
                tokenSettings.getAccessTokenTimeToLive().getSeconds());
        log.debug("  - Refresh Token TTL: {} seconds",
                tokenSettings.getRefreshTokenTimeToLive().getSeconds());

        return RegisteredClient.withId(entity.getId())
                .clientId(entity.getClientId())
                .clientSecret(entity.getClientSecret())
                .clientName(entity.getClientName())
                .clientAuthenticationMethods(methods ->
                        clientAuthenticationMethods.forEach(method ->
                                methods.add(CLIENT_AUTH_METHOD_CONVERTER.convert(method))))
                .authorizationGrantTypes(types ->
                        authorizationGrantTypes.forEach(type ->
                                types.add(new AuthorizationGrantType(type))))
                .redirectUris(uris -> redirectUris.forEach(uri -> uris.add(uri)))
                .postLogoutRedirectUris(uris -> postLogoutRedirectUris.forEach(uri -> uris.add(uri)))
                .scopes(s -> scopes.forEach(scope -> s.add(scope)))
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings)
                .build();
    }

    // ==================== SETTINGS PARSERS (Duration-safe) ====================

    /**
     *  Parse TokenSettings with Duration handling
     */
    static TokenSettings parseTokenSettings(String json) {
        if (!StringUtils.hasText(json)) {
            return defaultTokenSettings();
        }

        try {
            Map<String, Object> settings = parseMap(json);
            TokenSettings.Builder builder = TokenSettings.builder();

            // Access Token TTL - handle Duration or Number
            if (settings.containsKey("access-token-time-to-live")) {
                builder.accessTokenTimeToLive(parseDuration(settings.get("access-token-time-to-live")));
            } else {
                builder.accessTokenTimeToLive(Duration.ofMinutes(15));
            }

            // Refresh Token TTL
            if (settings.containsKey("refresh-token-time-to-live")) {
                builder.refreshTokenTimeToLive(parseDuration(settings.get("refresh-token-time-to-live")));
            } else {
                builder.refreshTokenTimeToLive(Duration.ofDays(30));
            }

            // Reuse refresh tokens
            if (settings.containsKey("reuse-refresh-tokens")) {
                builder.reuseRefreshTokens(Boolean.TRUE.equals(settings.get("reuse-refresh-tokens")));
            }

            // ID token signature algorithm
            if (settings.containsKey("id-token-signature-algorithm")) {
                String algo = settings.get("id-token-signature-algorithm").toString();
                builder.idTokenSignatureAlgorithm(SignatureAlgorithm.from(algo));
            }

            return builder.build();

        } catch (Exception e) {
            log.warn("Failed to parse TokenSettings, using defaults: {}", e.getMessage());
            return defaultTokenSettings();
        }
    }

    /**
     *  Parse ClientSettings
     */
    static ClientSettings parseClientSettings(String json) {
        if (!StringUtils.hasText(json)) {
            return defaultClientSettings();
        }

        try {
            Map<String, Object> settings = parseMap(json);
            ClientSettings.Builder builder = ClientSettings.builder();

            if (settings.containsKey("require-authorization-consent")) {
                builder.requireAuthorizationConsent(Boolean.TRUE.equals(settings.get("require-authorization-consent")));
            }

            if (settings.containsKey("require-proof-key")) {
                builder.requireProofKey(Boolean.TRUE.equals(settings.get("require-proof-key")));
            }

            return builder.build();

        } catch (Exception e) {
            log.warn("⚠️ Failed to parse ClientSettings, using defaults: {}", e.getMessage());
            return defaultClientSettings();
        }
    }

    /**
     * Smart Duration parser - handles both Duration objects and epoch seconds
     */
    private static Duration parseDuration(Object value) {
        if (value instanceof Duration) {
            return (Duration) value;
        } else if (value instanceof Number) {
            return Duration.ofSeconds(((Number) value).longValue());
        } else if (value instanceof String) {
            // Try ISO-8601 format first (e.g., "PT15M" or "PT30D")
            try {
                return Duration.parse((String) value);
            } catch (Exception e) {
                // Fallback: try as seconds number
                try {
                    return Duration.ofSeconds(Long.parseLong((String) value));
                } catch (NumberFormatException ex) {
                    log.warn("Cannot parse duration from string: {}", value);
                    return Duration.ofMinutes(15); // Default fallback
                }
            }
        } else {
            log.warn("Unknown duration type: {} ({})", value.getClass(), value);
            return Duration.ofMinutes(15); // Safe default
        }
    }

    private static TokenSettings defaultTokenSettings() {
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(15))
                .refreshTokenTimeToLive(Duration.ofDays(30))
                .reuseRefreshTokens(false)
                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
    }

    private static ClientSettings defaultClientSettings() {
        return ClientSettings.builder()
                .requireAuthorizationConsent(false)
                .requireProofKey(false)
                .build();
    }

    // ==================== AUTHORIZATION ====================

    static OAuth2AuthorizationEntity toEntity(OAuth2Authorization authorization) {
        Map<String, Object> attributes = authorization.getAttributes();

        OAuth2AuthorizationEntity entity = OAuth2AuthorizationEntity.builder()
                .id(authorization.getId())
                .registeredClientId(authorization.getRegisteredClientId())
                .principalName(authorization.getPrincipalName())
                .authorizationGrantType(authorization.getAuthorizationGrantType().getValue())
                .authorizedScopes(authorization.getAuthorizedScopes() != null ?
                        toJson(new ArrayList<>(authorization.getAuthorizedScopes())) : null)
                .attributes(!attributes.isEmpty() ? toJson(attributes) : null)
                .state(getState(attributes))
                .build();

        // Authorization code
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        if (authorizationCode != null) {
            entity.setAuthorizationCodeValue(authorizationCode.getToken().getTokenValue());
            entity.setAuthorizationCodeMetadata(writeAsJson(authorizationCode));
        }

        // Access token
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        if (accessToken != null) {
            entity.setAccessTokenValue(accessToken.getToken().getTokenValue());
            entity.setAccessTokenMetadata(writeAsJson(accessToken));
            entity.setAccessTokenType(accessToken.getToken().getTokenType().getValue());
            entity.setAccessTokenScopes(accessToken.getToken().getScopes() != null ?
                    toJson(new ArrayList<>(accessToken.getToken().getScopes())) : null);
        }

        // OIDC ID token
        OAuth2Authorization.Token<OidcIdToken> oidcIdToken =
                authorization.getToken(OidcIdToken.class);
        if (oidcIdToken != null) {
            entity.setOidcIdTokenValue(oidcIdToken.getToken().getTokenValue());
            entity.setOidcIdTokenMetadata(writeAsJson(oidcIdToken));
        }

        // Refresh token
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);
        if (refreshToken != null) {
            entity.setRefreshTokenValue(refreshToken.getToken().getTokenValue());
            entity.setRefreshTokenMetadata(writeAsJson(refreshToken));
        }

        return entity;
    }

    static OAuth2Authorization toObject(OAuth2AuthorizationEntity entity) {
        RegisteredClient registeredClient = RegisteredClient.withId(
                entity.getRegisteredClientId()).build();

        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(entity.getId())
                .principalName(entity.getPrincipalName())
                .authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantType()))
                .authorizedScopes(parseSet(entity.getAuthorizedScopes()))
                .attributes(attrs -> attrs.putAll(parseMap(entity.getAttributes())));

        if (entity.getState() != null) {
            builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
        }

        // Authorization code
        if (entity.getAuthorizationCodeValue() != null) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    entity.getAuthorizationCodeValue(),
                    issuedAt(entity.getAuthorizationCodeMetadata()),
                    expiresAt(entity.getAuthorizationCodeMetadata()));
            builder.token(authorizationCode, metadata -> metadata.putAll(parseMap(entity.getAuthorizationCodeMetadata())));
        }

        // Access token
        if (entity.getAccessTokenValue() != null) {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    entity.getAccessTokenValue(),
                    issuedAt(entity.getAccessTokenMetadata()),
                    expiresAt(entity.getAccessTokenMetadata()),
                    parseSet(entity.getAccessTokenScopes()));
            builder.token(accessToken, metadata -> metadata.putAll(parseMap(entity.getAccessTokenMetadata())));
        }

        // OIDC ID token
        if (entity.getOidcIdTokenValue() != null) {
            OidcIdToken oidcIdToken = new OidcIdToken(
                    entity.getOidcIdTokenValue(),
                    issuedAt(entity.getOidcIdTokenMetadata()),
                    expiresAt(entity.getOidcIdTokenMetadata()),
                    Collections.emptyMap());
            builder.token(oidcIdToken, metadata -> metadata.putAll(parseMap(entity.getOidcIdTokenMetadata())));
        }

        // Refresh token
        if (entity.getRefreshTokenValue() != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    entity.getRefreshTokenValue(),
                    issuedAt(entity.getRefreshTokenMetadata()),
                    expiresAt(entity.getRefreshTokenMetadata()));
            builder.token(refreshToken, metadata -> metadata.putAll(parseMap(entity.getRefreshTokenMetadata())));
        }

        return builder.build();
    }

    // ==================== AUTHORIZATION CONSENT ====================

    static OAuth2AuthorizationConsentEntity toEntity(OAuth2AuthorizationConsent consent) {
        return OAuth2AuthorizationConsentEntity.builder()
                .registeredClientId(consent.getRegisteredClientId())
                .principalName(consent.getPrincipalName())
                .authorities(toJson(consent.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet())))
                .build();
    }

    static OAuth2AuthorizationConsent toObject(OAuth2AuthorizationConsentEntity entity) {
        Set<String> authorityStrings = parseSet(entity.getAuthorities());

        OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(
                entity.getRegisteredClientId(),
                entity.getPrincipalName());

        authorityStrings.stream()
                .map(SimpleGrantedAuthority::new)
                .forEach(builder::authority);

        return builder.build();
    }

    // ==================== HELPERS ====================

    private static <T extends OAuth2Token> String writeAsJson(OAuth2Authorization.Token<T> token) {
        Map<String, Object> data = new HashMap<>();
        data.put("metadata", token.getMetadata());
        data.put("issuedAt", token.getToken().getIssuedAt().getEpochSecond());
        if (token.getToken().getExpiresAt() != null) {
            data.put("expiresAt", token.getToken().getExpiresAt().getEpochSecond());
        }
        return toJson(data);
    }

    private static Instant issuedAt(String json) {
        Map<String, Object> map = parseMap(json);
        Number issuedAt = (Number) map.get("issuedAt");
        return Instant.ofEpochSecond(issuedAt.longValue());
    }

    private static Instant expiresAt(String json) {
        Map<String, Object> map = parseMap(json);
        Number expiresAt = (Number) map.get("expiresAt");
        return expiresAt != null ? Instant.ofEpochSecond(expiresAt.longValue()) : null;
    }

    private static String getState(Map<String, Object> attributes) {
        if (attributes == null || attributes.isEmpty()) {
            return null;
        }
        return (String) attributes.get(OAuth2ParameterNames.STATE);
    }
}
