package com.pickfolio.auth.domain.response;

public record LoginResponse(String accessToken, String refreshToken) {
}
