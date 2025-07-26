package com.pickfolio.auth.domain.properties;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
@NoArgsConstructor
public class JwtProperties {
    private String secret;
    private Long accessTokenExpiryTime;
    private Long refreshTokenExpiryTime;
}
