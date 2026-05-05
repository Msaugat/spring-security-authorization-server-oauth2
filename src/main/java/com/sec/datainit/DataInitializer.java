package com.sec.datainit;
import com.sec.model.User;
import com.sec.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class DataInitializer {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public ApplicationRunner initializeUsers() {
        return args -> {
            if (!userRepository.existsByUsername("admin")) {
                User admin = User.builder()
                        .username("admin")
                        .password(passwordEncoder.encode("admin123"))
                        .email("admin@example.com")
                        .fullName("Admin User")
                        .roles(List.of("ROLE_ADMIN", "ROLE_USER"))
                        .enabled(true)
                        .build();
                userRepository.save(admin);
            }

            if (!userRepository.existsByUsername("user")) {
                User user = User.builder()
                        .username("user")
                        .password(passwordEncoder.encode("user123"))
                        .email("user@example.com")
                        .fullName("Regular User")
                        .roles(List.of("ROLE_USER"))
                        .enabled(true)
                        .build();
                userRepository.save(user);
            }
        };
    }
}
