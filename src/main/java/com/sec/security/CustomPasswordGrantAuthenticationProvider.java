package com.sec.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;

import java.security.Principal;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * ✅ Uses standard AuthenticationProvider interface (NOT OAuth2AuthenticationProvider)
 */

@Slf4j
@RequiredArgsConstructor
public class CustomPasswordGrantAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationManager authenticationManager;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2AuthorizationConsentService consentService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomPasswordGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        // Cast to our custom type
        CustomPasswordGrantAuthenticationToken passwordAuth =
                (CustomPasswordGrantAuthenticationToken) authentication;

        // Get registered client from our custom field
        RegisteredClient registeredClient = passwordAuth.getRegisteredClient();

        log.info("Processing password grant for client: {}", registeredClient.getClientId());
        log.info("Authenticating user: {}", passwordAuth.getUsername());

        // Validate client supports password grant
        if (!registeredClient.getAuthorizationGrantTypes().contains(new AuthorizationGrantType("password"))) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT),
                    "Client does not support password grant"
            );
        }

        // Authenticate user credentials via Spring Security
        Authentication userAuthentication;
        try {
            userAuthentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            passwordAuth.getUsername(),
                            passwordAuth.getPassword()
                    )
            );
        } catch (AuthenticationException e) {
            log.warn("Failed to authenticate user: {}", passwordAuth.getUsername());
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT),
                    "Invalid username or password"
            );
        }

        log.info("✅ User authenticated successfully: {}", passwordAuth.getUsername());

        // Determine authorized scopes
        Set<String> authorizedScopes = determineAuthorizedScopes(registeredClient, passwordAuth);

        //  BUILD TOKEN CONTEXT - NO .authorization() METHOD!
        DefaultOAuth2TokenContext.Builder contextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(userAuthentication)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(passwordAuth.getGrantType());
        // ⚠️⚠️⚠️ DO NOT ADD .authorization() HERE! ⚠️⚠️⚠️

        // Generate ACCESS TOKEN (JWT)
        OAuth2TokenContext accessTokenContext = contextBuilder
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();

        OAuth2AccessToken accessToken = generateAccessToken(accessTokenContext);

        // Generate REFRESH TOKEN
        OAuth2TokenContext refreshTokenContext = contextBuilder
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .build();

        OAuth2RefreshToken refreshToken = generateRefreshToken(refreshTokenContext);

        // Save authorization to database
        OAuth2Authorization.Builder authBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(passwordAuth.getUsername())
                .authorizationGrantType(passwordAuth.getGrantType())
                .authorizedScopes(authorizedScopes)
                .attribute(Principal.class.getName(), userAuthentication);

        if (accessToken != null) {
            authBuilder.token(accessToken);
        }
        if (refreshToken != null) {
            authBuilder.token(refreshToken);
        }

        OAuth2Authorization authorization = authBuilder.build();
        authorizationService.save(authorization);

        log.info("💾 Saved OAuth2 Authorization ID: {}", authorization.getId());

        // Return successful authentication with JWT tokens
        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                userAuthentication,
                accessToken,
                refreshToken,
                Collections.emptyMap()
        );
    }

    private OAuth2AccessToken generateAccessToken(OAuth2TokenContext context) {
        OAuth2Token token = tokenGenerator.generate(context);

        if (token instanceof OAuth2AccessToken) {
            return (OAuth2AccessToken) token;
        }

        throw new IllegalStateException("Expected access token but got: " +
                (token != null ? token.getClass().getSimpleName() : "null"));
    }

    private OAuth2RefreshToken generateRefreshToken(OAuth2TokenContext context) {
        OAuth2Token token = tokenGenerator.generate(context);

        if (token == null) {
            return null;
        }

        if (token instanceof OAuth2RefreshToken) {
            return (OAuth2RefreshToken) token;
        }

        throw new IllegalStateException("Expected refresh token but got: " + token.getClass().getSimpleName());
    }

    private Set<String> determineAuthorizedScopes(
            RegisteredClient registeredClient,
            CustomPasswordGrantAuthenticationToken passwordAuth) {

        Set<String> requestedScopes = passwordAuth.getScopes();

        if (requestedScopes.isEmpty()) {
            return registeredClient.getScopes();
        }

        return requestedScopes.stream()
                .filter(scope -> registeredClient.getScopes().contains(scope))
                .collect(Collectors.toSet());
    }
}
