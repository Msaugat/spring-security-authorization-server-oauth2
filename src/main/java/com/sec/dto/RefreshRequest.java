package com.sec.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

public record RefreshRequest(@NotBlank String refreshToken) {}
