package com.pickfolio.auth.service.impl;

import com.pickfolio.auth.domain.model.RefreshToken;
import com.pickfolio.auth.domain.model.User;
import com.pickfolio.auth.domain.properties.JwtProperties;
import com.pickfolio.auth.domain.request.LoginRequest;
import com.pickfolio.auth.domain.request.LogoutRequest;
import com.pickfolio.auth.domain.request.RefreshRequest;
import com.pickfolio.auth.domain.request.RegisterRequest;
import com.pickfolio.auth.domain.response.LoginResponse;
import com.pickfolio.auth.exception.InvalidCredentialsException;
import com.pickfolio.auth.exception.UsernameAlreadyExistsException;
import com.pickfolio.auth.repository.RefreshTokenRepository;
import com.pickfolio.auth.repository.UserRepository;
import com.pickfolio.auth.service.TokenService;
import com.pickfolio.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Collections;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final Logger logger = org.slf4j.LoggerFactory.getLogger(UserServiceImpl.class);
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final JwtProperties jwtProperties;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    @Transactional
    public void registerUser(final RegisterRequest request) {
        String username = request.getUsername().trim();
        if (userRepository.findByUsername(username).isPresent()) {
            throw new UsernameAlreadyExistsException(username);
        }

        User user = User.builder()
                .username(username)
                .password(passwordEncoder.encode(request.getPassword()))
                .name(request.getName())
                .build();

        userRepository.save(user);
        logger.info("User registered successfully: {}", user.getUsername());
    }

    @Override
    @Transactional
    public LoginResponse loginUser(final LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        User user = (User) authentication.getPrincipal();
        // Delete any existing refresh tokens for the user
        refreshTokenRepository.deleteAllByUserAndDeviceInfo(user, request.getDeviceInfo());
        logger.debug("Deleted existing refresh tokens for user: {} with device: {}", user.getUsername(), request.getDeviceInfo());

        String accessToken = tokenService.generateAccessToken(authentication);
        RefreshToken refreshToken = createRefreshToken(user, request.getDeviceInfo());
        logger.info("User logged in successfully: {}", user.getUsername());
        return new LoginResponse(accessToken, refreshToken.getToken());
    }

    @Override
    @Transactional
    public LoginResponse refreshAccessToken(RefreshRequest request) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new InvalidCredentialsException("Can't refresh access token: Provided refresh token is invalid"));

        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new InvalidCredentialsException("Refresh token expired. Please make a new login request");
        }

        User user = refreshToken.getUser();
        Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, Collections.emptyList());

        String newAccessToken = tokenService.generateAccessToken(authentication);
        logger.info("Access token refreshed for user: {}", user.getUsername());
        return new LoginResponse(newAccessToken, request.getRefreshToken());
    }

    @Override
    @Transactional
    public void logoutUser(LogoutRequest request) {
        if (request.getRefreshToken() == null || request.getRefreshToken().isEmpty()) {
            logger.error("Logout failed: refresh token is null or empty");
            throw new InvalidCredentialsException("Refresh token must be provided to logout");
        }

        refreshTokenRepository.findByToken(request.getRefreshToken())
                .ifPresentOrElse(
                        token -> {
                            refreshTokenRepository.delete(token);
                            logger.info("User logged out, refresh token invalidated: {}", token.getToken());
                        },
                        () -> {
                            logger.warn("Logout attempted with non-existing token: {}", request.getRefreshToken());
                            // Silently ignore to prevent token enumeration attacks.
                        }
                );
    }

    @Override
    @Transactional
    public void logoutUserFromAllDevices(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        User userToLogout;

        if (principal instanceof User) {
            // This case would happen if the method were called from a flow
            // authenticated by username/password.
            userToLogout = (User) principal;
        } else if (principal instanceof Jwt) {
            // This is the correct path for a request authenticated via JWT.
            String userIdString = ((Jwt) principal).getSubject();
            UUID userId = UUID.fromString(userIdString);

            // We must fetch the user from the database using the ID from the token.
            userToLogout = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found for ID: " + userId));
        } else {
            // This is a safeguard against unexpected principal types.
            throw new IllegalStateException("Unsupported principal type: " + principal.getClass().getName());
        }

        int deletedCount = refreshTokenRepository.deleteAllByUser(userToLogout);
        logger.info("User {} logged out from all devices. {} tokens deleted", userToLogout.getUsername(), deletedCount);
    }

    private RefreshToken createRefreshToken(User user, String deviceInfo) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(jwtProperties.getRefreshTokenExpiryTime()));
        refreshToken.setDeviceInfo(deviceInfo);
        return refreshTokenRepository.save(refreshToken);
    }

}