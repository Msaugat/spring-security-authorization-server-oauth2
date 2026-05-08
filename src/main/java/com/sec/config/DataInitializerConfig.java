package com.sec.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sec.entity.RegisteredClientEntity;
import com.sec.entity.Role;
import com.sec.enums.ERole;
import com.sec.repository.JpaRegisteredClientRepository;
import com.sec.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class DataInitializerConfig {

    private final JpaRegisteredClientRepository clientRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * ✅ Thread-safe ObjectMapper with JSR310 support for Duration serialization
     */
    private static final ObjectMapper OBJECT_MAPPER = createObjectMapper();

    private static ObjectMapper createObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());  // <-- CRITICAL for Duration support
        return mapper;
    }

    @Bean
    public CommandLineRunner initializeData() {
        return args -> {
            initializeRoles();
            initializeClients();
            log.info("✅ Data initialization completed successfully");
        };
    }

    private void initializeRoles() {
        for (ERole roleName : ERole.values()) {
            if (!roleRepository.findByName(roleName).isPresent()) {
                roleRepository.save(Role.builder()
                        .name(roleName)
                        .build());
                log.info("Created role: {}", roleName);
            }
        }
    }

    private void initializeClients() {
        if (clientRepository.findByClientId("react-spa-client").isEmpty()) {

            try {
                // ✅ Build settings as Maps (ObjectMapper will serialize Duration correctly)
                Map<String, Object> tokenSettings = new LinkedHashMap<>();
                tokenSettings.put("access-token-time-to-live", Duration.ofMinutes(15));   // 15 minutes
                tokenSettings.put("refresh-token-time-to-live", Duration.ofDays(30));     // 30 days
                tokenSettings.put("reuse-refresh-tokens", false);
                tokenSettings.put("id-token-signature-algorithm", "RS256");

                Map<String, Object> clientSettings = new LinkedHashMap<>();
                clientSettings.put("require-authorization-consent", false);
                clientSettings.put("require-proof-key", false);

                var client = RegisteredClientEntity.builder()
                        .id(UUID.randomUUID().toString())
                        .clientId("react-spa-client")
                        .clientSecret(passwordEncoder.encode("secret"))
                        .clientName("React SPA Client")

                        // Authentication methods
                        .clientAuthenticationMethods(toJson(List.of("client_secret_post")))

                        // Grant types
                        .authorizationGrantTypes(toJson(List.of(
                                "refresh_token",
                                "client_credentials",
                                "password"
                        )))

                        // URIs (empty for SPA with password grant)
                        .redirectUris(toJson(Collections.emptyList()))
                        .postLogoutRedirectUris(toJson(Collections.emptyList()))

                        // Scopes
                        .scopes(toJson(Arrays.asList(
                                "openid", "profile", "email", "read", "write"
                        )))

                        // Settings - will be serialized as ISO-8601 durations
                        .clientSettings(toJson(clientSettings))
                        .tokenSettings(toJson(tokenSettings))

                        .createdAt(LocalDateTime.now())
                        .build();

                // Save and verify
                RegisteredClientEntity saved = clientRepository.save(client);

                log.info("Created OAuth2 client: react-spa-client");
                log.info("Token Settings JSON:");
                log.info("   {}", formatJson(saved.getTokenSettings()));
                log.info("Client Settings JSON:");
                log.info("   {}", formatJson(saved.getClientSettings()));

            } catch (Exception e) {
                log.error("Failed to create OAuth2 client", e);
                throw new RuntimeException("Failed to initialize OAuth2 client", e);
            }
        } else {
            log.info("OAuth2 client already exists, skipping creation");
        }
    }

    /**
     * Serialize object to JSON string using configured ObjectMapper
     */
    private String toJson(Object obj) {
        try {
            return OBJECT_MAPPER.writeValueAsString(obj);
        } catch (Exception e) {
            throw new RuntimeException("JSON serialization failed for: " + obj.getClass().getSimpleName(), e);
        }
    }

    /**
     * Pretty-print JSON for logging
     */
    private String formatJson(String json) {
        try {
            Object parsed = OBJECT_MAPPER.readValue(json, Object.class);
            return OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(parsed);
        } catch (Exception e) {
            return json; // Return raw if pretty-print fails
        }
    }
}