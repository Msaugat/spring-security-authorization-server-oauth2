package com.sec.entity;


import jakarta.persistence.*;
import lombok.*;
import java.io.Serializable;

@Entity
@Table(name = "oauth2_authorization_consent",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = {"registered_client_id", "principal_name"})
        })
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
@IdClass(OAuth2AuthorizationConsentEntity.ConsentId.class)
public class OAuth2AuthorizationConsentEntity {

    @Id
    @Column(name = "registered_client_id", length = 100)
    private String registeredClientId;

    @Id
    @Column(name = "principal_name", length = 200)
    private String principalName;

    @Column(name = "authorities", columnDefinition = "TEXT")
    private String authorities;

    @Embeddable
    @Getter @Setter @NoArgsConstructor @AllArgsConstructor
    public static class ConsentId implements Serializable {
        private String registeredClientId;
        private String principalName;
    }
}
