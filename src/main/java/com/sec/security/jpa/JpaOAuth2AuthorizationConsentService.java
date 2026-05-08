package com.sec.security.jpa;

import com.sec.entity.OAuth2AuthorizationConsentEntity;
import com.sec.repository.JpaOAuth2AuthorizationConsentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

@Component
@RequiredArgsConstructor
@Transactional
public class JpaOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private final JpaOAuth2AuthorizationConsentRepository consentRepository;

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        this.consentRepository.save(toEntity(authorizationConsent));
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        var consentId = new OAuth2AuthorizationConsentEntity.ConsentId();
        consentId.setRegisteredClientId(authorizationConsent.getRegisteredClientId());
        consentId.setPrincipalName(authorizationConsent.getPrincipalName());
        this.consentRepository.deleteById(consentId);
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        return this.consentRepository.findByRegisteredClientIdAndPrincipalName(registeredClientId, principalName)
                .map(this::toObject)
                .orElse(null);
    }

    private OAuth2AuthorizationConsentEntity toEntity(OAuth2AuthorizationConsent consent) {
        return JpaConverters.toEntity(consent);
    }

    private OAuth2AuthorizationConsent toObject(OAuth2AuthorizationConsentEntity entity) {
        return JpaConverters.toObject(entity);
    }
}
