package com.pickfolio.auth.service;

import com.pickfolio.auth.domain.request.LoginRequest;
import com.pickfolio.auth.domain.request.LogoutRequest;
import com.pickfolio.auth.domain.request.RefreshRequest;
import com.pickfolio.auth.domain.request.RegisterRequest;
import com.pickfolio.auth.domain.response.LoginResponse;
import org.springframework.security.core.Authentication;

public interface UserService {

    void registerUser(RegisterRequest request);

    LoginResponse loginUser(LoginRequest request);

    LoginResponse refreshAccessToken(RefreshRequest request);

    void logoutUser(LogoutRequest request);

    void logoutUserFromAllDevices(Authentication authentication);
}
