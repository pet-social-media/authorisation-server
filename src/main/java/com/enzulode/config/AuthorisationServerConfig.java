package com.enzulode.config;

import com.enzulode.config.properties.AuthorizationServerKeysProperties;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * This class contains authorisation server-relates configurations.
 */
@Configuration
public class AuthorisationServerConfig {

    private final AuthorizationServerKeysProperties keysProperties;

    public AuthorisationServerConfig(AuthorizationServerKeysProperties keysProperties) {
        this.keysProperties = keysProperties;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        http
                .oauth2ResourceServer( (resourceServer) -> resourceServer.jwt(Customizer.withDefaults()) )
                .cors(Customizer.withDefaults())
                .exceptionHandling(
                        (exceptions) -> exceptions
                                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                );
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(Customizer.withDefaults())
                .csrf(Customizer.withDefaults())
                .authorizeHttpRequests( (requestAuth) -> requestAuth
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        List<AuthorizationServerKeysProperties.RsaKeyPair> pairs = keysProperties.getRsa().stream()
                .filter( Objects::nonNull )
                .filter( el -> Objects.nonNull(el.publicKey) && Objects.nonNull(el.privateKey) )
                .toList();

        if (pairs.isEmpty())
            throw new RuntimeException(
                    "Authorization server configuration failure: jwk source cannot be initialized with no keys"
            );

        List<JWK> keys = pairs.stream()
                .map(pair -> new RSAKey.Builder(pair.publicKey)
                        .privateKey(pair.privateKey)
                        .keyID(UUID.randomUUID().toString())
                        .build()
                )
                .map(key -> (JWK) key)
                .toList();

        JWKSet keySet = new JWKSet(keys);
        return new ImmutableJWKSet<>(keySet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings
                .builder()
                .build();
    }
}
