package com.sec.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sec.model.OAuth2Authorization;
import com.sec.repository.OAuth2AuthorizationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Service
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final OAuth2AuthorizationRepository authorizationRepository;
    private final RegisteredClientRepository registeredClientRepository; // FIX: Need this to load client
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JpaOAuth2AuthorizationService(OAuth2AuthorizationRepository authorizationRepository,
                                         RegisteredClientRepository registeredClientRepository) {
        this.authorizationRepository = authorizationRepository;
        this.registeredClientRepository = registeredClientRepository;
        ClassLoader classLoader = JpaOAuth2AuthorizationService.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    }

    @Override
    @Transactional
    public void save(org.springframework.security.oauth2.server.authorization.OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        this.authorizationRepository.save(toEntity(authorization));
    }

    @Override
    @Transactional
    public void remove(org.springframework.security.oauth2.server.authorization.OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        this.authorizationRepository.deleteById(authorization.getId());
    }

    @Override
    @Transactional(readOnly = true)
    public org.springframework.security.oauth2.server.authorization.OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return this.authorizationRepository.findById(id).map(this::toObject).orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public org.springframework.security.oauth2.server.authorization.OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");

        OAuth2Authorization result;
        if (tokenType == null) {
            result = this.authorizationRepository.findByAnyToken(token).orElse(null);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByState(token).orElse(null);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByAuthorizationCodeValue(token).orElse(null);
        } else if (OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByAccessTokenValue(token).orElse(null);
        } else if (OAuth2ParameterNames.REFRESH_TOKEN.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByRefreshTokenValue(token).orElse(null);
        } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByOidcIdTokenValue(token).orElse(null);
        } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByUserCodeValue(token).orElse(null);
        } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByDeviceCodeValue(token).orElse(null);
        } else {
            result = null;
        }

        return result != null ? toObject(result) : null;
    }

    // ========================================
    // FIX: Use OAuth2Authorization.withRegisteredClient(registeredClient)
    // This is the OFFICIAL API from Spring docs [^33^]
    // ========================================
    private org.springframework.security.oauth2.server.authorization.OAuth2Authorization toObject(OAuth2Authorization entity) {

        // FIX #1: Load the full RegisteredClient object
        RegisteredClient registeredClient = this.registeredClientRepository.findById(entity.getRegisteredClientId());
        if (registeredClient == null) {
            throw new DataRetrievalFailureException(
                    "The RegisteredClient with id '" + entity.getRegisteredClientId() + "' was not found in the RegisteredClientRepository.");
        }

        // FIX #2: Use withRegisteredClient(registeredClient) - official API
        org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder builder =
                org.springframework.security.oauth2.server.authorization.OAuth2Authorization.withRegisteredClient(registeredClient)
                        .id(entity.getId())
                        .principalName(entity.getPrincipalName())
                        .authorizationGrantType(resolveAuthorizationGrantType(entity.getAuthorizationGrantType()))
                        .authorizedScopes(StringUtils.commaDelimitedListToSet(entity.getAuthorizedScopes()))
                        // FIX #3: attributes.putAll() works directly - no cast needed
                        .attributes(attributes -> attributes.putAll(parseMap(entity.getAttributes())));

        if (entity.getState() != null) {
            builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
        }

        if (entity.getAuthorizationCodeValue() != null) {
            org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode authorizationCode =
                    new org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode(
                            entity.getAuthorizationCodeValue(),
                            entity.getAuthorizationCodeIssuedAt(),
                            entity.getAuthorizationCodeExpiresAt());
            // FIX #4: metadata.putAll() works directly - Consumer<Map<String, Object>>
            builder.token(authorizationCode, metadata -> metadata.putAll(parseMap(entity.getAuthorizationCodeMetadata())));
        }

        if (entity.getAccessTokenValue() != null) {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    entity.getAccessTokenValue(),
                    entity.getAccessTokenIssuedAt(),
                    entity.getAccessTokenExpiresAt(),
                    StringUtils.commaDelimitedListToSet(entity.getAccessTokenScopes()));
            builder.token(accessToken, metadata -> metadata.putAll(parseMap(entity.getAccessTokenMetadata())));
        }

        if (entity.getRefreshTokenValue() != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    entity.getRefreshTokenValue(),
                    entity.getRefreshTokenIssuedAt(),
                    entity.getRefreshTokenExpiresAt());
            builder.token(refreshToken, metadata -> metadata.putAll(parseMap(entity.getRefreshTokenMetadata())));
        }

        if (entity.getOidcIdTokenValue() != null) {
            OidcIdToken idToken = new OidcIdToken(
                    entity.getOidcIdTokenValue(),
                    entity.getOidcIdTokenIssuedAt(),
                    entity.getOidcIdTokenExpiresAt(),
                    parseMap(entity.getOidcIdTokenClaims()));
            builder.token(idToken, metadata -> metadata.putAll(parseMap(entity.getOidcIdTokenMetadata())));
        }

        if (entity.getUserCodeValue() != null) {
            OAuth2UserCode userCode = new OAuth2UserCode(
                    entity.getUserCodeValue(),
                    entity.getUserCodeIssuedAt(),
                    entity.getUserCodeExpiresAt());
            builder.token(userCode, metadata -> metadata.putAll(parseMap(entity.getUserCodeMetadata())));
        }

        if (entity.getDeviceCodeValue() != null) {
            OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(
                    entity.getDeviceCodeValue(),
                    entity.getDeviceCodeIssuedAt(),
                    entity.getDeviceCodeExpiresAt());
            builder.token(deviceCode, metadata -> metadata.putAll(parseMap(entity.getDeviceCodeMetadata())));
        }

        return builder.build();
    }

    private OAuth2Authorization toEntity(org.springframework.security.oauth2.server.authorization.OAuth2Authorization authorization) {
        OAuth2Authorization entity = new OAuth2Authorization();
        entity.setId(authorization.getId());
        entity.setRegisteredClientId(authorization.getRegisteredClientId());
        entity.setPrincipalName(authorization.getPrincipalName());
        entity.setAuthorizationGrantType(authorization.getAuthorizationGrantType().getValue());
        entity.setAuthorizedScopes(StringUtils.collectionToCommaDelimitedString(authorization.getAuthorizedScopes()));
        entity.setAttributes(writeMap(authorization.getAttributes()));
        entity.setState(authorization.getAttribute(OAuth2ParameterNames.STATE));

        org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token<org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode.class);
        setTokenValues(
                authorizationCode,
                entity::setAuthorizationCodeValue,
                entity::setAuthorizationCodeIssuedAt,
                entity::setAuthorizationCodeExpiresAt,
                entity::setAuthorizationCodeMetadata
        );

        org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        setTokenValues(
                accessToken,
                entity::setAccessTokenValue,
                entity::setAccessTokenIssuedAt,
                entity::setAccessTokenExpiresAt,
                entity::setAccessTokenMetadata
        );
        if (accessToken != null && accessToken.getToken().getScopes() != null) {
            entity.setAccessTokenScopes(StringUtils.collectionToCommaDelimitedString(accessToken.getToken().getScopes()));
        }

        org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);
        setTokenValues(
                refreshToken,
                entity::setRefreshTokenValue,
                entity::setRefreshTokenIssuedAt,
                entity::setRefreshTokenExpiresAt,
                entity::setRefreshTokenMetadata
        );

        org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token<OidcIdToken> oidcIdToken =
                authorization.getToken(OidcIdToken.class);
        setTokenValues(
                oidcIdToken,
                entity::setOidcIdTokenValue,
                entity::setOidcIdTokenIssuedAt,
                entity::setOidcIdTokenExpiresAt,
                entity::setOidcIdTokenMetadata
        );
        if (oidcIdToken != null) {
            entity.setOidcIdTokenClaims(writeMap(oidcIdToken.getClaims()));
        }

        org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token<OAuth2UserCode> userCode =
                authorization.getToken(OAuth2UserCode.class);
        setTokenValues(
                userCode,
                entity::setUserCodeValue,
                entity::setUserCodeIssuedAt,
                entity::setUserCodeExpiresAt,
                entity::setUserCodeMetadata
        );

        org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode =
                authorization.getToken(OAuth2DeviceCode.class);
        setTokenValues(
                deviceCode,
                entity::setDeviceCodeValue,
                entity::setDeviceCodeIssuedAt,
                entity::setDeviceCodeExpiresAt,
                entity::setDeviceCodeMetadata
        );

        return entity;
    }

    private void setTokenValues(
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token<?> token,
            java.util.function.Consumer<String> tokenValueConsumer,
            java.util.function.Consumer<Instant> issuedAtConsumer,
            java.util.function.Consumer<Instant> expiresAtConsumer,
            java.util.function.Consumer<String> metadataConsumer) {

        if (token != null) {
            tokenValueConsumer.accept(token.getToken().getTokenValue());
            issuedAtConsumer.accept(token.getToken().getIssuedAt());
            expiresAtConsumer.accept(token.getToken().getExpiresAt());
            metadataConsumer.accept(writeMap(token.getMetadata()));
        }
    }

    private Map<String, Object> parseMap(String data) {
        try {
            return this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {});
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    private String writeMap(Map<String, Object> data) {
        try {
            return this.objectMapper.writeValueAsString(data);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    private static org.springframework.security.oauth2.core.AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS;
        } else if (org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN;
        } else if (org.springframework.security.oauth2.core.AuthorizationGrantType.DEVICE_CODE.getValue().equals(authorizationGrantType)) {
            return org.springframework.security.oauth2.core.AuthorizationGrantType.DEVICE_CODE;
        }
        return new org.springframework.security.oauth2.core.AuthorizationGrantType(authorizationGrantType);
    }
}