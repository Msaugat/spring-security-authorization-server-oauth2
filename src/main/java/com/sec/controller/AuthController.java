package com.sec.controller;


import com.sec.dto.AuthResponse;
import com.sec.dto.LoginRequest;
import com.sec.dto.RefreshTokenRequest;
import com.sec.dto.RegisterRequest;
import com.sec.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
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
     * Login - tries multiple OAuth2 authentication methods
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody LoginRequest request) {

        log.info("🔐 Login attempt for user: {}", request.getUsername());

        String tokenUrl = "http://localhost:8080/oauth2/token";

        // Use Method 2 ONLY (Form Parameters) since that's what works!
        try {
            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("grant_type", "password");
            formData.add("client_id", "react-spa-client");
            formData.add("client_secret", "secret");
            formData.add("username", request.getUsername());
            formData.add("password", request.getPassword());

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(formData, headers);

            log.info(" Calling OAuth2 token endpoint with Form Parameters...");

            ResponseEntity<Map> oauthResponse = restTemplate.postForEntity(tokenUrl, entity, Map.class);

            if (oauthResponse.getStatusCode().is2xxSuccessful() && oauthResponse.getBody() != null) {
                log.info(" Login successful for user: {}", request.getUsername());

                return ResponseEntity.ok(Map.of(
                        "accessToken", oauthResponse.getBody().get("access_token"),
                        "refreshToken", oauthResponse.getBody().get("refresh_token"),
                        "tokenType", oauthResponse.getBody().get("token_type"),
                        "expiresIn", oauthResponse.getBody().get("expires_in")
                ));
            } else {
                log.warn(" Unexpected response status: {}", oauthResponse.getStatusCode());
                return ResponseEntity.status(oauthResponse.getStatusCode())
                        .body(Map.of("error", "oauth2_error", "details", oauthResponse.getBody()));
            }

        } catch (org.springframework.web.client.HttpClientErrorException.Unauthorized e) {
            log.error("Login failed (401): {}", e.getResponseBodyAsString());

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "error", "authentication_failed",
                            "message", "Invalid credentials",
                            "debug", e.getResponseBodyAsString()
                    ));

        } catch (Exception e) {
            log.error("Login failed with exception: {}", e.getMessage(), e);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "server_error", "message", e.getMessage()));
        }
    }

    /**
     * Build standardized success response
     */
    private Map<String, Object> buildSuccessResponse(Map<String, Object> oauth2Response) {
        return Map.of(
                "accessToken", oauth2Response.get("access_token"),
                "refreshToken", oauth2Response.get("refresh_token"),
                "tokenType", oauth2Response.get("token_type"),
                "expiresIn", oauth2Response.get("expires_in")
        );
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<Map<String, Object>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {

        log.info("🔄 Refresh token request");

        String tokenUrl = "http://localhost:8080/oauth2/token";

        try {
            // Use Basic Auth for refresh too
            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("grant_type", "refresh_token");
            formData.add("refresh_token", request.getRefreshToken());

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            String credentials = "react-spa-client:secret";
            headers.set("Authorization", "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes()));

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(formData, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, entity, Map.class);

            log.info("✅ Token refreshed successfully");

            return ResponseEntity.ok(Map.of(
                    "accessToken", response.getBody().get("access_token"),
                    "refreshToken", response.getBody().get("refresh_token"),
                    "tokenType", response.getBody().get("token_type"),
                    "expiresIn", response.getBody().get("expires_in")
            ));

        } catch (Exception e) {
            log.error(" Refresh token failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid refresh token", "message", e.getMessage()));
        }
    }
}