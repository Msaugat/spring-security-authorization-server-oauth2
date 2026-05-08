package com.sec.config;


import com.sec.entity.RegisteredClientEntity;
import com.sec.enums.ERole;
import com.sec.repository.JpaRegisteredClientRepository;
import com.sec.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class DataInitializerConfig {

    private final JpaRegisteredClientRepository clientRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public CommandLineRunner initializeData() {
        return args -> {
            initializeRoles();
            initializeClients();
        };
    }

    private void initializeRoles() {
        for (ERole roleName : ERole.values()) {
            if (!roleRepository.findByName(roleName).isPresent()) {
                roleRepository.save(com.sec.entity.Role.builder()
                        .name(roleName)
                        .build());
                log.info("Initialized role: {}", roleName);
            }
        }
    }

    private void initializeClients() {
        if (clientRepository.findByClientId("react-spa-client").isEmpty()) {

            // Build client settings properly
            Set<ClientAuthenticationMethod> authMethods = Set.of(ClientAuthenticationMethod.CLIENT_SECRET_POST);
            Set<AuthorizationGrantType> grantTypes = Set.of(
                    AuthorizationGrantType.PASSWORD,      // Custom grant type for login
                    AuthorizationGrantType.REFRESH_TOKEN,
                    AuthorizationGrantType.CLIENT_CREDENTIALS
            );
            Set<String> scopes = Set.of("openid", "profile", "email", "read", "write");

            var client = RegisteredClientEntity.builder()
                    .id(UUID.randomUUID().toString())
                    .clientId("react-spa-client")
                    .clientSecret(passwordEncoder.encode("secret"))
                    .clientName("React SPA Client")
                    // Convert sets to JSON strings
                    .clientAuthenticationMethods(toJson(authMethods.stream()
                            .map(ClientAuthenticationMethod::getValue)
                            .collect(Collectors.toSet())))
                    .authorizationGrantTypes(toJson(grantTypes.stream()
                            .map(AuthorizationGrantType::getValue)
                            .collect(Collectors.toSet())))
                    .redirectUris("[]")
                    .postLogoutRedirectUris("[]")
                    .scopes(toJson(scopes))
                    // Client settings
                    .clientSettings("{\"requireAuthorizationConsent\":false,\"requireProofKey\":false}")
                    // Token settings with proper Duration format
                    .tokenSettings(buildTokenSettingsJson())
                    .createdAt(LocalDateTime.now())
                    .build();

            clientRepository.save(client);
            log.info("Initialized OAuth2 client: react-spa-client");
        }
    }

    private String buildTokenSettingsJson() {
        // Token settings using Duration-based configuration
        // Access token: 15 minutes
        // Refresh token: 30 days
        return "{"
                + "\"access-token-time-to-live\":" + Duration.ofMinutes(15).toSeconds() + ","
                + "\"refresh-token-time-to-live\":" + Duration.ofDays(30).toSeconds() + ","
                + "\"reuse-refresh-tokens\":false,"
                + "\"id-token-signature-algorithm\":\"RS256\""
                + "}";
    }

    private String toJson(Object obj) {
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            return mapper.writeValueAsString(obj);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize to JSON", e);
        }
    }
}
