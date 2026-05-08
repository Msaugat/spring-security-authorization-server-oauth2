package com.sec.security.jpa;


import com.sec.entity.OAuth2AuthorizationEntity;
import com.sec.repository.JpaOAuth2AuthorizationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

@Component
@RequiredArgsConstructor
@Transactional
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final JpaOAuth2AuthorizationRepository authorizationRepository;

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        this.authorizationRepository.save(toEntity(authorization));
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        this.authorizationRepository.deleteById(authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return this.authorizationRepository.findById(id)
                .map(this::toObject)
                .orElse(null);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");

        // Search by access token or refresh token value
        var result = this.authorizationRepository.findByAccessTokenValue(token);
        if (result.isEmpty()) {
            result = this.authorizationRepository.findByRefreshTokenValue(token);
        }

        return result.map(this::toObject).orElse(null);
    }

    private OAuth2AuthorizationEntity toEntity(OAuth2Authorization authorization) {
        return JpaConverters.toEntity(authorization);
    }

    private OAuth2Authorization toObject(OAuth2AuthorizationEntity entity) {
        return JpaConverters.toObject(entity);
    }
}
