package com.vapps.security.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.AntPathMatcher;

@Configuration
public class DefaultConfigurations {

    @Bean
    @ConditionalOnMissingBean(AntPathMatcher.class)
    public AntPathMatcher antPathMatcher() {
        return new AntPathMatcher();
    }

}
