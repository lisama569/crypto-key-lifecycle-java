package com.github.lisama569.cryptokeylifecyclejava.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(KeyLifecycleProperties.class)
public class KeyLifecycleConfig {
}
