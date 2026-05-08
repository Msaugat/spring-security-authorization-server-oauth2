package com.sec.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class CustomPasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final RegisteredClient registeredClient;
    private final String username;
    private final String password;
    private final Set<String> scopes;

    public CustomPasswordGrantAuthenticationToken(
            Authentication principal,
            RegisteredClient registeredClient,
            String username,
            String password,
            Set<String> scopes,
            Map<String, Object> additionalParameters) {

        super(
                new AuthorizationGrantType("password"),
                principal,
                additionalParameters
        );

        this.registeredClient = registeredClient;
        this.username = username;
        this.password = password;
        this.scopes = scopes != null ? Collections.unmodifiableSet(scopes) : Collections.emptySet();
    }

    public RegisteredClient getRegisteredClient() {
        return this.registeredClient;
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }
}
