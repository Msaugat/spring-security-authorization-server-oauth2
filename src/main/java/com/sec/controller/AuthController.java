package com.sec.controller;


import com.sec.dto.AuthResponse;
import com.sec.dto.LoginRequest;
import com.sec.dto.RefreshTokenRequest;
import com.sec.dto.RegisterRequest;
import com.sec.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.Map;


@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RestTemplate restTemplate = new RestTemplate();

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    /**
     * Login endpoint - proxies to OAuth2 /oauth2/token with password grant
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody LoginRequest request,
                                                     HttpServletRequest httpRequest) {

        log.info("Login request for user: {}", request.getUsername());

        // Build OAuth2 token request
        String tokenUrl = "http://localhost:8080/oauth2/token";

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "password");
        formData.add("client_id", "react-spa-client");
        formData.add("client_secret", "secret");
        formData.add("username", request.getUsername());
        formData.add("password", request.getPassword());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(formData, headers);

        try {
            // Call OAuth2 token endpoint (generates real JWT!)
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, entity, Map.class);

            Map<String, Object> oauth2Response = response.getBody();

            log.info("✅ Login successful for user: {}", request.getUsername());

            // Transform response to our format
            return ResponseEntity.ok(Map.of(
                    "accessToken", oauth2Response.get("access_token"),
                    "refreshToken", oauth2Response.get("refresh_token"),
                    "tokenType", oauth2Response.get("token_type"),
                    "expiresIn", oauth2Response.get("expires_in")
            ));

        } catch (Exception e) {
            log.error("Login failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid credentials", "message", e.getMessage()));
        }
    }

    /**
     * Refresh token endpoint - proxies to OAuth2 /oauth2/token with refresh_token grant
     */
    @PostMapping("/refresh-token")
    public ResponseEntity<Map<String, Object>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {

        log.info("Refresh token request");

        String tokenUrl = "http://localhost:8080/oauth2/token";

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "refresh_token");
        formData.add("client_id", "react-spa-client");
        formData.add("client_secret", "secret");
        formData.add("refresh_token", request.getRefreshToken());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(formData, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, entity, Map.class);
            Map<String, Object> oauth2Response = response.getBody();

            log.info("✅ Token refreshed successfully");

            return ResponseEntity.ok(Map.of(
                    "accessToken", oauth2Response.get("access_token"),
                    "refreshToken", oauth2Response.get("refresh_token"),
                    "tokenType", oauth2Response.get("token_type"),
                    "expiresIn", oauth2Response.get("expires_in")
            ));

        } catch (Exception e) {
            log.error("Refresh token failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid refresh token", "message", e.getMessage()));
        }
    }
}
