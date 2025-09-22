package com.pickfolio.auth.service;

import com.pickfolio.auth.domain.request.LoginRequest;
import com.pickfolio.auth.domain.request.LogoutRequest;
import com.pickfolio.auth.domain.request.RefreshRequest;
import com.pickfolio.auth.domain.request.RegisterRequest;
import com.pickfolio.auth.domain.response.LoginResponse;
import com.pickfolio.auth.domain.response.UserDetailResponse;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.UUID;

public interface UserService {

    void registerUser(RegisterRequest request);

    LoginResponse loginUser(LoginRequest request);

    LoginResponse refreshAccessToken(RefreshRequest request);

    void logoutUser(LogoutRequest request);

    void logoutUserFromAllDevices(Authentication authentication);

    List<UserDetailResponse> findUserDetailsByIds(List<UUID> userIds);
}
