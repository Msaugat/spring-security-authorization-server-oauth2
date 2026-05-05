package com.sec.model;

import jakarta.persistence.*;
import lombok.*;


@Entity
@Table(name = "oauth2_registered_client")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OAuth2Client {

    @Id
    @Column(length = 100)
    private String id;

    @Column(unique = true, nullable = false, length = 100)
    private String clientId;

    private java.time.Instant clientIdIssuedAt;

    @Column(length = 200)
    private String clientSecret;

    private java.time.Instant clientSecretExpiresAt;

    @Column(nullable = false, length = 200)
    private String clientName;

    @Column(nullable = false, length = 1000)
    private String clientAuthenticationMethods;

    @Column(nullable = false, length = 1000)
    private String authorizationGrantTypes;

    @Column(nullable = false, length = 1000)
    private String redirectUris;

    @Column(length = 1000)
    private String postLogoutRedirectUris;

    @Column(nullable = false, length = 1000)
    private String scopes;

    @Column(length = 2000)
    private String clientSettings;

    @Column(length = 2000)
    private String tokenSettings;
}
