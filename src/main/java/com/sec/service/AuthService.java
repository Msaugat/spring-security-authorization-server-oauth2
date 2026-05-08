package com.sec.service;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.sec.dto.AuthResponse;
import com.sec.dto.LoginRequest;
import com.sec.dto.RefreshTokenRequest;
import com.sec.dto.RegisterRequest;
import com.sec.entity.Role;
import com.sec.entity.User;
import com.sec.enums.ERole;
import com.sec.repository.RoleRepository;
import com.sec.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final PasswordEncoder passwordEncoder;
    private static final ObjectMapper mapper = new ObjectMapper();

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(userRole))
                .build();

        userRepository.save(user);

        return authenticate(new LoginRequest(request.getUsername(), request.getPassword()));
    }

    public AuthResponse authenticate(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        // FIX #1: findByClientId now returns Optional<RegisteredClient>
        RegisteredClient registeredClient = registeredClientRepository
                .findByClientId("react-spa-client");

        if (registeredClient == null) {
            throw new RuntimeException("Client not found");
        }

        Instant issuedAt = Instant.now();

        // FIX #2: Use Duration-based getters for token settings
        Duration accessTokenTTL = registeredClient.getTokenSettings().getAccessTokenTimeToLive();
        Duration refreshTokenTTL = registeredClient.getTokenSettings().getRefreshTokenTimeToLive();

        Set<String> scopes = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        // Create access token
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                UUID.randomUUID().toString(),
                issuedAt,
                issuedAt.plus(accessTokenTTL),
                scopes
        );

        // Create refresh token
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                UUID.randomUUID().toString(),
                issuedAt,
                issuedAt.plus(refreshTokenTTL)
        );

        // Save authorization
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(authentication.getName())
                .authorizationGrantType(new org.springframework.security.oauth2.core.AuthorizationGrantType("password"))
                .authorizedScopes(scopes)
                .attribute("principal", authentication.getPrincipal())
                .token(accessToken)
                .token(refreshToken)
                .build();

        authorizationService.save(authorization);

        return AuthResponse.builder()
                .accessToken(accessToken.getTokenValue())
                .refreshToken(refreshToken.getTokenValue())
                .expiresIn(accessTokenTTL.getSeconds())
                .build();
    }

    public AuthResponse refreshToken(RefreshTokenRequest request) {
        OAuth2Authorization authorization = authorizationService.findByToken(
                request.getRefreshToken(),
                OAuth2TokenType.REFRESH_TOKEN);

        RegisteredClient registeredClient = registeredClientRepository.findById(
                authorization.getRegisteredClientId());

        // Validate refresh token is not expired
        OAuth2RefreshToken currentRefreshToken = authorization.getRefreshToken().getToken();
        if (currentRefreshToken.getExpiresAt().isBefore(Instant.now())) {
            authorizationService.remove(authorization);
            throw new RuntimeException("Refresh token expired");
        }

        Instant issuedAt = Instant.now();

        // FIX #3: Correct way to get TTL values
        Duration accessTokenTTL = registeredClient.getTokenSettings().getAccessTokenTimeToLive();
        Duration refreshTokenTTL = registeredClient.getTokenSettings().getRefreshTokenTimeToLive();

        Set<String> scopes = authorization.getAuthorizedScopes();

        // Create new access token
        OAuth2AccessToken newAccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                UUID.randomUUID().toString(),
                issuedAt,
                issuedAt.plus(accessTokenTTL),
                scopes
        );

        // Rotate refresh token
        OAuth2RefreshToken newRefreshToken = new OAuth2RefreshToken(
                UUID.randomUUID().toString(),
                issuedAt,
                issuedAt.plus(refreshTokenTTL)
        );

        // Update authorization with new tokens
        OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
                .token(newAccessToken)
                .token(newRefreshToken)
                .build();

        authorizationService.remove(authorization);
        authorizationService.save(updatedAuthorization);

        return AuthResponse.builder()
                .accessToken(newAccessToken.getTokenValue())
                .refreshToken(newRefreshToken.getTokenValue())
                .expiresIn(accessTokenTTL.getSeconds())
                .build();
    }
}
