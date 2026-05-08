package com.sec.repository;

import com.sec.entity.OAuth2AuthorizationConsentEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JpaOAuth2AuthorizationConsentRepository
        extends JpaRepository<OAuth2AuthorizationConsentEntity, OAuth2AuthorizationConsentEntity.ConsentId> {

    Optional<OAuth2AuthorizationConsentEntity>
    findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}
