package com.sec.config;


/**
 * CUSTOM FILTER: Handles password grant BEFORE Authorization Server processes it!
 * Intercepts /oauth2/token?grant_type=password requests
 */

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component; // ✅ ADD THIS!
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.Principal;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Custom Filter: Handles password grant BEFORE Authorization Server
 */
@Slf4j
@Component
public class PasswordGrantFilter extends OncePerRequestFilter {

    @Lazy
    @Autowired
    private AuthenticationManager authenticationManager;


    @Autowired
    private OAuth2AuthorizationService authorizationService;

    @Lazy
    @Autowired
    private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (shouldHandlePasswordGrant(request)) {

            log.info("═══════════════════════════════════════");
            log.info("🔐 [PasswordGrantFilter] Intercepting password grant!");

            try {
                boolean handled = processPasswordGrant(request, response);
                if (handled) return;

            } catch (Exception e) {
                log.error("Failed: {}", e.getMessage());
                sendErrorResponse(response, 400, "invalid_grant", e.getMessage());
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean shouldHandlePasswordGrant(HttpServletRequest request) {
        boolean match = "POST".equalsIgnoreCase(request.getMethod())
                && "/oauth2/token".equals(request.getRequestURI())
                && "password".equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE));

        if (match) log.debug("[Filter] Intercepting password grant request");
        return match;
    }

    private boolean processPasswordGrant(HttpServletRequest request, HttpServletResponse response) throws Exception {

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        if (!(clientPrincipal instanceof OAuth2ClientAuthenticationToken)) {
            sendErrorResponse(response, 401, "invalid_client", "Client not authenticated");
            return true;
        }

        RegisteredClient client = ((OAuth2ClientAuthenticationToken) clientPrincipal).getRegisteredClient();
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        log.info("   Client: {} | User: {}", client.getClientId(), username);

        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            sendErrorResponse(response, 400, "invalid_request", "Missing credentials");
            return true;
        }

        // Authenticate user
        log.info("Authenticating user...");
        Authentication userAuth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );
        log.info("User authenticated!");

        // Scopes
        Set<String> scopes = determineScopes(client, request);

        // Generate Access Token
        log.info("Generating JWT...");

        DefaultOAuth2TokenContext.Builder contextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .principal(userAuth)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(scopes)
                .authorizationGrantType(new AuthorizationGrantType("password"));

        OAuth2TokenContext accessTokenContext = contextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedToken = tokenGenerator.generate(accessTokenContext);
        OAuth2AccessToken accessToken = convertToAccessToken(generatedToken, scopes);

        log.info("Token: {}...", accessToken.getTokenValue().substring(0, Math.min(30, accessToken.getTokenValue().length())));

        // Generate Refresh Token
        OAuth2TokenContext refreshTokenContext = contextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
        OAuth2Token generatedRefreshToken = tokenGenerator.generate(refreshTokenContext);
        OAuth2RefreshToken refreshToken = convertToRefreshToken(generatedRefreshToken);
        if (refreshToken != null) log.info("Refresh token created");

        // Save authorization
        log.info("Saving...");
        OAuth2Authorization.Builder authBuilder = OAuth2Authorization.withRegisteredClient(client)
                .principalName(username)
                .authorizationGrantType(new AuthorizationGrantType("password"))
                .authorizedScopes(scopes)
                .attribute(Principal.class.getName(), userAuth)
                .token(accessToken);
        if (refreshToken != null) authBuilder.token(refreshToken);

        authorizationService.save(authBuilder.build());
        log.info("Saved!");

        // Write response
        writeSuccessResponse(response, accessToken, refreshToken);
        return true;
    }

    private OAuth2AccessToken convertToAccessToken(OAuth2Token token, Set<String> scopes) {
        if (token instanceof Jwt) {
            Jwt jwt = (Jwt) token;
            return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                    jwt.getTokenValue(), jwt.getIssuedAt(),
                    jwt.getExpiresAt() != null ? jwt.getExpiresAt() : Instant.now().plusSeconds(900), scopes);
        } else if (token instanceof OAuth2AccessToken) {
            return (OAuth2AccessToken) token;
        }
        throw new IllegalStateException("Unexpected token type: " + token.getClass());
    }

    private OAuth2RefreshToken convertToRefreshToken(OAuth2Token token) {
        if (token == null) return null;
        if (token instanceof OAuth2RefreshToken) return (OAuth2RefreshToken) token;
        return new OAuth2RefreshToken(token.getTokenValue(), token.getIssuedAt(), token.getExpiresAt());
    }

    private Set<String> determineScopes(RegisteredClient client, HttpServletRequest request) {
        String scopeParam = request.getParameter(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scopeParam)) {
            Set<String> requested = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scopeParam, " ")));
            return requested.stream().filter(s -> client.getScopes().contains(s)).collect(Collectors.toSet());
        }
        return client.getScopes();
    }

    private void writeSuccessResponse(HttpServletResponse response, OAuth2AccessToken accessToken, OAuth2RefreshToken refreshToken) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", accessToken.getTokenValue());
        body.put("token_type", accessToken.getTokenType().getValue());
        body.put("expires_in", accessToken.getExpiresAt().getEpochSecond() - System.currentTimeMillis() / 1000);
        body.put("scope", String.join(" ", accessToken.getScopes()));
        if (refreshToken != null) body.put("refresh_token", refreshToken.getTokenValue());

        response.setStatus(200);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(body));
        log.info("🎉 Response written!");
    }

    private void sendErrorResponse(HttpServletResponse response, int status, String error, String desc) throws IOException {
        Map<String, String> body = Map.of("error", error, "error_description", desc);
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(body));
    }
}
