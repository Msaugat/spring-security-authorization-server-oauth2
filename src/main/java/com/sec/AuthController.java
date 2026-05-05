package com.sec;


import com.sec.dto.ApiResponse;
import com.sec.dto.LoginRequest;
import com.sec.dto.RefreshRequest;
import com.sec.dto.TokenResponse;
import com.sec.service.InternalOAuth2TokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final InternalOAuth2TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<TokenResponse>> login(@Valid @RequestBody LoginRequest request) {
        try {
            TokenResponse tokens = tokenService.authenticateAndGenerateTokens(
                    request.getUsername(),
                    request.getPassword()
            );
            return ResponseEntity.ok(ApiResponse.success(tokens));
        } catch (Exception e) {
            return ResponseEntity.status(401).body(ApiResponse.error(e.getMessage()));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<TokenResponse>> refresh(@Valid @RequestBody RefreshRequest request) {
        try {
            TokenResponse tokens = tokenService.refreshAccessToken(request.getRefreshToken());
            return ResponseEntity.ok(ApiResponse.success(tokens));
        } catch (Exception e) {
            return ResponseEntity.status(401).body(ApiResponse.error(e.getMessage()));
        }
    }
}
