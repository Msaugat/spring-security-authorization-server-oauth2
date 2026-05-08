package com.sec.repository;

import com.sec.entity.OAuth2AuthorizationEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JpaOAuth2AuthorizationRepository extends JpaRepository<OAuth2AuthorizationEntity, String> {
    Optional<OAuth2AuthorizationEntity> findByAccessTokenValue(String tokenValue);

    Optional<OAuth2AuthorizationEntity> findByRefreshTokenValue(String refreshTokenValue);

}