package com.sec.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

public record TokenResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn,
        String scope,
        String username,
        // Optional: return the authorization code if client wants to complete flow manually
        String authorizationCode
) {}
