package com.sec;


import com.sec.dto.ApiResponse;
import com.sec.dto.LoginRequest;
import com.sec.dto.RefreshRequest;
import com.sec.dto.TokenResponse;
import com.sec.service.InternalOAuth2TokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final InternalOAuth2TokenService tokenService;

    /**
     * Hybrid PKCE Login Endpoint
     *
     * - If codeChallenge is provided: Uses full PKCE flow (more secure)
     * - If codeChallenge is null: Falls back to direct token issuance (for trusted clients)
     *
     * Returns tokens in your custom ApiResponse format.
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<TokenResponse>> login(@Valid @RequestBody LoginRequest request) {
        try {
            log.debug("Login attempt for user: {}", request.username());

            TokenResponse tokens = tokenService.authenticateAndGenerateTokens(
                    request.username(),
                    request.password(),
                    request.codeChallenge(),
                    request.scope()
            );

            log.info("Login successful for user: {}", request.username());
            return ResponseEntity.ok(ApiResponse.success(tokens));

        } catch (OAuth2AuthenticationException e) {
            log.warn(" Auth failed for {}: {}", request.username(), e.getError().getDescription());
            return ResponseEntity.status(401).body(ApiResponse.error(e.getError().getDescription()));
        } catch (IllegalArgumentException e) {
            log.warn(" Invalid request: {}", e);
            return ResponseEntity.badRequest().body(ApiResponse.error(e.getMessage()));
        } catch (Exception e) {
            log.error("Unexpected error during login for {}", request.username(), e);
            return ResponseEntity.status(500).body(ApiResponse.error("Authentication failed"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<TokenResponse>> refresh(@Valid @RequestBody RefreshRequest request) {
        try {
            TokenResponse tokens = tokenService.refreshAccessToken(request.refreshToken());
            return ResponseEntity.ok(ApiResponse.success(tokens));
        } catch (OAuth2AuthenticationException e) {
            return ResponseEntity.status(401).body(ApiResponse.error(e.getError().getDescription()));
        } catch (Exception e) {
            return ResponseEntity.status(401).body(ApiResponse.error("Invalid or expired refresh token"));
        }
    }
}