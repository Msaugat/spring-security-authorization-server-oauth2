package com.sec.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

public record LoginRequest(
        @NotBlank String username,
        @NotBlank String password,
        // Optional: PKCE code challenge (S256 method recommended)
        @Size(min = 43, max = 128, message = "code_challenge must be 43-128 chars")
        String codeChallenge,
        // Optional: requested scopes (defaults to client's registered scopes)
        String scope
) {
}


