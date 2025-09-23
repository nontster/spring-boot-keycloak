package com.n12g.demo.keycloak;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthConverter.class);

    // Converter to get the default "SCOPE_" authorities
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String resourceId; // e.g., your client-id in Keycloak

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        // Use our central extractor to get custom roles
        Collection<GrantedAuthority> authorities = KeycloakRoleExtractor.extractResourceRoles(jwt.getClaims(), resourceId);

        // Combine with default scope-based authorities if needed
        Collection<GrantedAuthority> scopeAuthorities = jwtGrantedAuthoritiesConverter.convert(jwt);

        Set<GrantedAuthority> allAuthorities = Stream.concat(authorities.stream(), scopeAuthorities.stream())
                .collect(Collectors.toSet());

        return new JwtAuthenticationToken(jwt, allAuthorities, getPrincipalClaimName(jwt));
    }

    private String getPrincipalClaimName(Jwt jwt) {
        // Use "sub" or a custom claim like "preferred_username"
        return jwt.getClaim("preferred_username");
    }
}
