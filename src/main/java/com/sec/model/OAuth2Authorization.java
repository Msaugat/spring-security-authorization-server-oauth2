package com.sec.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "oauth2_authorization")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OAuth2Authorization {

    @Id
    @Column(length = 100)
    private String id;

    @Column(length = 100)
    private String registeredClientId;

    @Column(length = 200)
    private String principalName;

    @Column(length = 100)
    private String authorizationGrantType;

    @Column(length = 1000)
    private String authorizedScopes;

    @Column(length = 4000)
    private String attributes;

    @Column(length = 500)
    private String state;

    @Column(length = 4000)
    private String authorizationCodeValue;

    private Instant authorizationCodeIssuedAt;
    private Instant authorizationCodeExpiresAt;

    @Column(length = 2000)
    private String authorizationCodeMetadata;

    @Column(length = 4000)
    private String accessTokenValue;

    private Instant accessTokenIssuedAt;
    private Instant accessTokenExpiresAt;

    @Column(length = 2000)
    private String accessTokenMetadata;

    @Column(length = 100)
    private String accessTokenType;

    @Column(length = 1000)
    private String accessTokenScopes;

    @Column(length = 4000)
    private String refreshTokenValue;

    private Instant refreshTokenIssuedAt;
    private Instant refreshTokenExpiresAt;

    @Column(length = 2000)
    private String refreshTokenMetadata;

    @Column(length = 4000)
    private String oidcIdTokenValue;

    private Instant oidcIdTokenIssuedAt;
    private Instant oidcIdTokenExpiresAt;

    @Column(length = 2000)
    private String oidcIdTokenMetadata;

    @Column(length = 2000)
    private String oidcIdTokenClaims;

    @Column(length = 4000)
    private String userCodeValue;

    private Instant userCodeIssuedAt;
    private Instant userCodeExpiresAt;

    @Column(length = 2000)
    private String userCodeMetadata;

    @Column(length = 4000)
    private String deviceCodeValue;

    private Instant deviceCodeIssuedAt;
    private Instant deviceCodeExpiresAt;

    @Column(length = 2000)
    private String deviceCodeMetadata;
}
