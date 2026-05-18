package com.pickfolio.auth.config;

import com.pickfolio.auth.domain.model.User;
import com.pickfolio.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataSeeder implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        log.info("Checking for AI Bot accounts...");
        seedBot("warren_bot", "WarrenBot \uD83E\uDD16", "VALUE");
        seedBot("chad_bot", "ChadBot \uD83E\uDD16", "WSB_YOLO");
        seedBot("quant_bot", "QuantBot \uD83E\uDD16", "MOMENTUM");
        seedBot("analyst_bot", "AnalystBot \uD83E\uDD16", "AI_ANALYST");
        log.info("Data seeding completed.");
    }

    private void seedBot(String username, String name, String personaType) {
        if (userRepository.findByUsername(username).isEmpty()) {
            log.info("Creating bot account: {}", username);
            User bot = User.builder()
                    .username(username)
                    .name(name)
                    .password(passwordEncoder.encode(username + "_secret_123!")) // Random complex password
                    .isBot(true)
                    .personaType(personaType)
                    .build();
            userRepository.save(bot);
        }
    }
}
