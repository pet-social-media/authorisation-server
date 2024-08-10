package com.enzulode;

import com.enzulode.config.properties.AuthorizationServerKeysProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;


@SpringBootApplication
@EnableDiscoveryClient
@EnableConfigurationProperties({ AuthorizationServerKeysProperties.class })
public class SocialMediaAuthorisationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(SocialMediaAuthorisationServerApplication.class, args);
    }
}
