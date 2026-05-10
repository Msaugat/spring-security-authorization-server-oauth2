package com.sec.service;

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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final PasswordEncoder passwordEncoder;

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
        log.info("User registered successfully: {}", request.getUsername());

        // Return success message (user can now login)
        return AuthResponse.builder()
                .message("Registration successful")
                .build();
    }

    /**
     * Login returns tokens by calling standard OAuth2 /oauth2/token endpoint internally
     */
    public AuthResponse authenticate(LoginRequest request) {
        log.info("Processing login for user: {}", request.getUsername());

        // This will be handled by AuthController calling the OAuth2 endpoint directly
        // or you can delegate to the custom provider here

        // For simplicity, we'll just validate user exists and let controller handle token generation
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        return AuthResponse.builder()
                .message("Call POST /oauth2/token with grant_type=password&username=...&password=...")
                .build();
    }

    public AuthResponse refreshToken(RefreshTokenRequest request) {
        log.info("Processing refresh token");

        OAuth2Authorization authorization = authorizationService.findByToken(
                        request.getRefreshToken(),
                        OAuth2TokenType.REFRESH_TOKEN);


        if(authorization == null){
            throw new RuntimeException("Invalid refresh token");
        }

        // Validate not expired
        OAuth2RefreshToken currentRefreshToken = authorization.getRefreshToken().getToken();
        if (currentRefreshToken.getExpiresAt().isBefore(Instant.now())) {
            authorizationService.remove(authorization);
            throw new RuntimeException("Refresh token has expired");
        }

        // Get client
        RegisteredClient registeredClient = registeredClientRepository.findById(
                        authorization.getRegisteredClientId());

        if(registeredClient == null){
            throw new RuntimeException("Client not found");
        }

        authorizationService.remove(authorization);

        log.info("Refresh token validated successfully. Call POST /oauth2/token with grant_type=refresh_token");

        return AuthResponse.builder()
                .message("Call POST /oauth2/token with grant_type=refresh_token&refresh_token=...")
                .build();
    }
}