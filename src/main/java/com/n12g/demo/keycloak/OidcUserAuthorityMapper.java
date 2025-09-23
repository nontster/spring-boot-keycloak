package com.n12g.demo.keycloak;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * This class maps the authorities from the OIDC user to Spring Security authorities.
 * It extracts the roles from the OIDC user's claims and adds them to the set of authorities.
 */
@Component
public class OidcUserAuthorityMapper implements GrantedAuthoritiesMapper {
    private static final Logger LOGGER = LoggerFactory.getLogger(OidcUserAuthorityMapper.class);

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String resourceId;

    /**
     * This method maps the authorities from the OIDC user to Spring Security authorities.
     * It extracts the roles from the OIDC user's claims and adds them to the set of authorities.
     * @param authorities The authorities from the OIDC user.
     * @return The mapped authorities.
     */
    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

        authorities.forEach(authority -> {
            if (authority instanceof OidcUserAuthority oidcUserAuthority) {
                // Extract roles from the OIDC user's claims using our central logic
                Collection<GrantedAuthority> roles = KeycloakRoleExtractor.extractResourceRoles(
                        oidcUserAuthority.getIdToken().getClaims(), resourceId
                );
                LOGGER.info("roles: {}", roles);
                mappedAuthorities.addAll(roles);
            }
        });

        return mappedAuthorities;
    }
}