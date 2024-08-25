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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.*;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * This class contains authorisation server-relates configurations.
 */
@Configuration
public class AuthorisationServerConfig {

    private final AuthorizationServerKeysProperties keysProperties;

    private final String LOGIN_PAGE = "http://127.0.0.1:4200/login";
    private final String LOGOUT_PROCESSING_URL = "/api/v1/logout";
    private final String LOGIN_PROCESSING_URL = "/api/v1/login";

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
                .cors(Customizer.withDefaults())
                .exceptionHandling( (exceptions) -> exceptions
                                .defaultAuthenticationEntryPointFor(
                                        new LoginUrlAuthenticationEntryPoint(LOGIN_PAGE),
                                        new MediaTypeRequestMatcher(MediaType.APPLICATION_JSON)
                                )
                )
                .oauth2ResourceServer( (resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults())
                );
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // CSRF configuration
        CookieCsrfTokenRepository tokenRepo = CookieCsrfTokenRepository.withHttpOnlyFalse();
        tokenRepo.setCookiePath("/");

        XorCsrfTokenRequestAttributeHandler delegate = new XorCsrfTokenRequestAttributeHandler();
        delegate.setCsrfRequestAttributeName(null);

        http
                .cors(Customizer.withDefaults())
                .csrf( (csrf) -> csrf
                        .csrfTokenRepository(tokenRepo)  // disabled for local development purposes
                        .csrfTokenRequestHandler(delegate::handle)
                )
                .formLogin( (formLogin) -> formLogin
                        .loginPage(LOGIN_PAGE)
                        .loginProcessingUrl(LOGIN_PROCESSING_URL)
                        .successHandler( (req, res, auth) -> {
                            res.resetBuffer();
                            res.setStatus(HttpStatus.OK.value());
                            res.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
                            var savedReq = (new HttpSessionRequestCache()).getRequest(req, res);
                            res.getWriter()
                                    .append("{\"redirectUrl\": \"")
                                    .append(savedReq == null ? "" : savedReq.getRedirectUrl())
                                    .append("\"}");
                            res.flushBuffer();
                        })
                        .failureHandler( (req, res, auth) -> res
                                .setStatus(HttpStatus.UNAUTHORIZED.value())
                        )
                )
                .logout( (logout) -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher(LOGOUT_PROCESSING_URL, "GET"))
                        .deleteCookies("JSESSIONID")
                )
                .exceptionHandling( (handler) -> handler
                        .authenticationEntryPoint(
                                new HttpStatusEntryPoint(HttpStatus.FORBIDDEN)
                        )
                )
                .authorizeHttpRequests( (authorize) -> authorize
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/api/v1/csrf").permitAll()
                        .requestMatchers("/api/v1/logout").permitAll()
                        .anyRequest().authenticated()
                );

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
