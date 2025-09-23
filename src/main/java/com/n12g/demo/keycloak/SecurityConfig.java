package com.n12g.demo.keycloak;

import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;

/**
 * This class provides the security configuration for the application. It
 * defines the security filter chains for both the API and the web UI. It also
 * configures the OAuth2 login and resource server.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityConfig.class);

    private final JwtAuthConverter jwtAuthConverter; // For Resource Server
    private final OidcUserAuthorityMapper oidcUserAuthorityMapper; // For OAuth2 Login
    private final ClientRegistrationRepository clientRegistrationRepository;

    /**
     * This constructor injects the required dependencies.
     *
     * @param jwtAuthConverter The JWT authentication converter.
     * @param oidcUserAuthorityMapper The OIDC user authority mapper.
     * @param clientRegistrationRepository The client registration repository.
     */
    public SecurityConfig(JwtAuthConverter jwtAuthConverter, OidcUserAuthorityMapper oidcUserAuthorityMapper, ClientRegistrationRepository clientRegistrationRepository) {
        this.jwtAuthConverter = jwtAuthConverter;
        this.oidcUserAuthorityMapper = oidcUserAuthorityMapper;
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    /**
     * This method configures the OIDC logout success handler. It sets the
     * post-logout redirect URI to the base URL.
     *
     * @return The OIDC client-initiated logout success handler.
     */
    private OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);
        successHandler.setPostLogoutRedirectUri("{baseUrl}");
        return successHandler;
    }

    /**
     * This method configures the security filter chain for the API. It secures
     * all endpoints under /api/** and requires the USER or ADMIN role. It also
     * configures the OAuth2 resource server to use JWT authentication.
     *
     * @param http The HTTP security object.
     * @return The security filter chain for the API.
     * @throws Exception If an error occurs.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**")
                .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/user/**").hasRole("USER")
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
                );
        // Configure OAuth2 Resource Server for API
        http
                .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter))
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable()); // Configure OAuth2 Login for UI

        return http.build();
    }

    /**
     * This method configures the security filter chain for the web UI. It
     * secures the /profile endpoint and requires the USER or ADMIN role. It
     * also configures the OAuth2 login with a custom OIDC user service.
     *
     * @param http The HTTP security object.
     * @return The security filter chain for the web UI.
     * @throws Exception If an error occurs.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                .requestMatchers("/").permitAll()
                .requestMatchers("/profile").hasAnyRole("USER", "ADMIN")
                .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfo -> userInfo
                .oidcUserService(this.oidcUserService())
                )
                )
                .logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler())
                );

        return http.build();
    }

    /**
     * This method provides a custom OIDC user service. It maps the authorities
     * from the OIDC user to Spring Security authorities.
     *
     * @return The custom OIDC user service.
     */
    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            OidcUser oidcUser = delegate.loadUser(userRequest);
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>(oidcUser.getAuthorities());
            mappedAuthorities.addAll(oidcUserAuthorityMapper.mapAuthorities(oidcUser.getAuthorities()));

            return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
        };
    }
}
