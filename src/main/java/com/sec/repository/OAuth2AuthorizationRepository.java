package com.sec.repository;


import com.sec.model.OAuth2Authorization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuth2AuthorizationRepository extends JpaRepository<OAuth2Authorization, String> {

    Optional<OAuth2Authorization> findByState(String state);

    Optional<OAuth2Authorization> findByAuthorizationCodeValue(String authorizationCode);

    Optional<OAuth2Authorization> findByAccessTokenValue(String accessToken);

    Optional<OAuth2Authorization> findByRefreshTokenValue(String refreshToken);

    Optional<OAuth2Authorization> findByOidcIdTokenValue(String idToken);

    Optional<OAuth2Authorization> findByUserCodeValue(String userCode);

    Optional<OAuth2Authorization> findByDeviceCodeValue(String deviceCode);

    @Query("select a from OAuth2Authorization a where a.state = :token" +
            " or a.authorizationCodeValue = :token" +
            " or a.accessTokenValue = :token" +
            " or a.refreshTokenValue = :token" +
            " or a.oidcIdTokenValue = :token" +
            " or a.userCodeValue = :token" +
            " or a.deviceCodeValue = :token")
    Optional<OAuth2Authorization> findByAnyToken(@Param("token") String token);
}
