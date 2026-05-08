package com.sec.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "registered_client")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class RegisteredClientEntity {

    @Id
    @Column(length = 100)
    private String id;

    @Column(nullable = false, length = 100)
    private String clientId;

    @Column(length = 500)
    private String clientSecret;

    @Column(name = "client_name", length = 200)
    private String clientName;

    @Column(name = "client_authentication_methods", columnDefinition = "TEXT", nullable = false)
    private String clientAuthenticationMethods;

    @Column(name = "authorization_grant_types", columnDefinition = "TEXT", nullable = false)
    private String authorizationGrantTypes;

    @Column(name = "redirect_uris", columnDefinition = "TEXT")
    private String redirectUris;

    @Column(name = "post_logout_redirect_uris", columnDefinition = "TEXT")
    private String postLogoutRedirectUris;

    @Column(name = "scopes", columnDefinition = "TEXT", nullable = false)
    private String scopes;

    @Column(name = "client_settings", columnDefinition = "TEXT", nullable = false)
    private String clientSettings;

    @Column(name = "token_settings", columnDefinition = "TEXT", nullable = false)
    private String tokenSettings;

    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;
}
