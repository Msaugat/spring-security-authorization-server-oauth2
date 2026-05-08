package com.sec.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Converts HTTP POST /oauth2/token?grant_type=password → CustomPasswordGrantAuthenticationToken
 */
public class CustomPasswordGrantAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {

        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return null;
        }

        if (!"/oauth2/token".equals(request.getRequestURI())) {
            return null;
        }

        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!"password".equals(grantType)) {
            return null;
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        if (!(clientPrincipal instanceof OAuth2ClientAuthenticationToken)) {
            return null;
        }

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            return null;
        }

        String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
        Set<String> requestedScopes;

        if (StringUtils.hasText(scope)) {
            requestedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        } else {
            requestedScopes = Collections.emptySet();
        }

        RegisteredClient registeredClient = ((OAuth2ClientAuthenticationToken) clientPrincipal).getRegisteredClient();

        return new CustomPasswordGrantAuthenticationToken(
                clientPrincipal,
                registeredClient,
                username,
                password,
                requestedScopes,
                Collections.emptyMap()
        );
    }
}
