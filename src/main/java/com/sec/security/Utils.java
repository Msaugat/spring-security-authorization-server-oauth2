package com.sec.security;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sec.entity.OAuth2AuthorizationConsentEntity;
import com.sec.entity.OAuth2AuthorizationEntity;
import com.sec.entity.RegisteredClientEntity;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

final class Utils {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // Converter for ClientAuthenticationMethod
    private static final Converter<String, ClientAuthenticationMethod> CLIENT_AUTHENTICATION_METHOD_CONVERTER =
            new Converter<String, ClientAuthenticationMethod>() {
                @Override
                public ClientAuthenticationMethod convert(String source) {
                    return new ClientAuthenticationMethod(source);
                }
            };

    static String toJson(Object object) {
        try {
            return OBJECT_MAPPER.writeValueAsString(object);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    static <T> T fromJson(String json, TypeReference<T> typeReference) {
        if (!StringUtils.hasText(json)) {
            return null;
        }
        try {
            return OBJECT_MAPPER.readValue(json, typeReference);
        } catch (IOException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    static Set<String> parseSet(String json) {
        return fromJson(json, new TypeReference<Set<String>>() {});
    }

    static Map<String, Object> parseMap(String json) {
        return fromJson(json, new TypeReference<Map<String, Object>>() {});
    }

    static RegisteredClient toRegisteredClient(RegisteredClientEntity entity) {
        Set<String> clientAuthenticationMethods = parseSet(entity.getClientAuthenticationMethods());
        Set<String> authorizationGrantTypes = parseSet(entity.getAuthorizationGrantTypes());
        Set<String> redirectUris = parseSet(entity.getRedirectUris());
        Set<String> postLogoutRedirectUris = parseSet(entity.getPostLogoutRedirectUris());
        Set<String> scopes = parseSet(entity.getScopes());
        ClientSettings clientSettings = fromJson(entity.getClientSettings(),
                new TypeReference<ClientSettings>() {});
        TokenSettings tokenSettings = fromJson(entity.getTokenSettings(),
                new TypeReference<TokenSettings>() {});

        var builder = RegisteredClient.withId(entity.getId())
                .clientId(entity.getClientId())
                .clientSecret(entity.getClientSecret())
                .clientName(entity.getClientName())
                // FIX: Use converter instead of valueOf for ClientAuthenticationMethod
                .clientAuthenticationMethods(methods ->
                        clientAuthenticationMethods.forEach(method ->
                                methods.add(CLIENT_AUTHENTICATION_METHOD_CONVERTER.convert(method))))
                .authorizationGrantTypes(types ->
                        authorizationGrantTypes.forEach(type ->
                                types.add(new AuthorizationGrantType(type))))
                .redirectUris(uris -> redirectUris.forEach(uri -> uris.add(uri)))
                .postLogoutRedirectUris(uris -> postLogoutRedirectUris.forEach(uri -> uris.add(uri)))
                .scopes(s -> scopes.forEach(scope -> s.add(scope)))
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings);

        return builder.build();
    }

    static OAuth2AuthorizationEntity toEntity(OAuth2Authorization authorization) {
        var entity = new OAuth2AuthorizationEntity();
        entity.setId(authorization.getId());
        entity.setRegisteredClientId(authorization.getRegisteredClientId());
        entity.setPrincipalName(authorization.getPrincipalName());
        entity.setAuthorizationGrantType(
                authorization.getAuthorizationGrantType().getValue());
        entity.setAuthorizedScopes(authorization.getAuthorizedScopes() != null ?
                toJson(authorization.getAuthorizedScopes()) : null);
        entity.setAttributes(authorization.getAttributes() != null ?
                toJson(authorization.getAttributes()) : null);

        // Authorization code
        var authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);
        if (authorizationCode != null) {
            entity.setAuthorizationCodeValue(authorizationCode.getToken().getTokenValue());
            entity.setAuthorizationCodeMetadata(toMetadata(authorizationCode).toString());
        }

        // Access token
        var accessToken = authorization.getToken(OAuth2AccessToken.class);
        if (accessToken != null) {
            entity.setAccessTokenValue(accessToken.getToken().getTokenValue());
            entity.setAccessTokenMetadata(toMetadata(accessToken).toString());
            entity.setAccessTokenType(accessToken.getToken().getTokenType().getValue());
            entity.setAccessTokenScopes(accessToken.getToken().getScopes() != null ?
                    toJson(accessToken.getToken().getScopes()) : null);
        }

        // OIDC ID token - FIX: Correct import and usage
        var oidcIdToken = authorization.getToken(OidcIdToken.class);
        if (oidcIdToken != null) {
            entity.setOidcIdTokenValue(oidcIdToken.getToken().getTokenValue());
            entity.setOidcIdTokenMetadata(toMetadata(oidcIdToken).toString());
        }

        // Refresh token - FIX: Proper casting for generic type
        var refreshToken = authorization.getToken(OAuth2RefreshToken.class);
        if (refreshToken != null) {
            entity.setRefreshTokenValue(refreshToken.getToken().getTokenValue());
            // FIX: Cast to proper type
            entity.setRefreshTokenMetadata(toMetadata((OAuth2Authorization.Token<? extends OAuth2Token>) refreshToken).toString());
        }

        return entity;
    }

    static OAuth2Authorization toObject(OAuth2AuthorizationEntity entity) {
        var registeredClient = RegisteredClient.withId(entity.getRegisteredClientId()).build();

        var builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(entity.getId())
                .principalName(entity.getPrincipalName())
                .authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantType()))
                .authorizedScopes(parseSet(entity.getAuthorizedScopes()))
                .attributes(attributes -> attributes.putAll(parseMap(entity.getAttributes())));

        if (entity.getAuthorizationCodeValue() != null) {
            var metadata = parseMap(entity.getAuthorizationCodeMetadata());
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    entity.getAuthorizationCodeValue(),
                    Instant.ofEpochSecond(((Number) metadata.get("issuedAt")).longValue()),
                    Instant.ofEpochSecond(((Number) metadata.get("expiresAt")).longValue()));
            builder.token(authorizationCode, metadata1 -> metadata1.putAll(metadata));
        }

        if (entity.getAccessTokenValue() != null) {
            var metadata = parseMap(entity.getAccessTokenMetadata());
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    entity.getAccessTokenValue(),
                    Instant.ofEpochSecond(((Number) metadata.get("issuedAt")).longValue()),
                    Instant.ofEpochSecond(((Number) metadata.get("expiresAt")).longValue()),
                    parseSet(entity.getAccessTokenScopes()));
            builder.token(accessToken, metadata1 -> metadata1.putAll(metadata));
        }

        if (entity.getRefreshTokenValue() != null) {
            var metadata = parseMap(entity.getRefreshTokenMetadata());
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    entity.getRefreshTokenValue(),
                    Instant.ofEpochSecond(((Number) metadata.get("issuedAt")).longValue()),
                    Instant.ofEpochSecond(((Number) metadata.get("expiresAt")).longValue()));
            builder.token(refreshToken, metadata1 -> metadata1.putAll(metadata));
        }

        return builder.build();
    }

    static Map<String, Object> toMetadata(OAuth2Authorization.Token<? extends OAuth2Token> token) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("issuedAt", token.getToken().getIssuedAt().getEpochSecond());
        if (token.getToken().getExpiresAt() != null) {
            metadata.put("expiresAt", token.getToken().getExpiresAt().getEpochSecond());
        }
        if (!token.getMetadata().isEmpty()) {
            metadata.putAll(token.getMetadata());
        }
        return metadata;
    }

    static OAuth2AuthorizationConsent toAuthorizationConsent(OAuth2AuthorizationConsentEntity entity) {
        var consent = OAuth2AuthorizationConsent.withId(
                entity.getRegisteredClientId(),
                entity.getPrincipalName());

        Set<String> authorityStrings = fromJson(entity.getAuthorities(),
                new TypeReference<Set<String>>() {});
        if (authorityStrings != null) {
            authorityStrings.stream()
                    .map(SimpleGrantedAuthority::new)
                    .forEach(consent::authority);
        }

        return consent.build();
    }
}
