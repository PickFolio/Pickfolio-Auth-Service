package com.pickfolio.auth.controller;

import com.pickfolio.auth.domain.response.UserDetailResponse;
import com.pickfolio.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/internal/users")
@RequiredArgsConstructor
public class InternalUserController {

    private final UserService userService;

    @PostMapping("/details")
    public ResponseEntity<List<UserDetailResponse>> getUserDetails(@RequestBody List<UUID> userIds) {
        return ResponseEntity.ok(userService.findUserDetailsByIds(userIds));
    }
}
