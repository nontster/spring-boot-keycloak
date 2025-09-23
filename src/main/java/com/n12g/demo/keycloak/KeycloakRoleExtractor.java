package com.n12g.demo.keycloak;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This class provides a utility method for extracting roles from a JWT claims map.
 * It can extract both realm roles and client-specific roles.
 */
public class KeycloakRoleExtractor {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakRoleExtractor.class);

    private static final String REALM_ACCESS = "realm_access";
    private static final String RESOURCE_ACCESS = "resource_access";
    private static final String ROLES = "roles";
    private static final String ROLE_PREFIX = "ROLE_";

    /**
     * Extracts roles from the JWT claims map.
     *
     * @param claims The claims map from the JWT.
     * @param resourceClientId The client ID of the resource.
     * @return A collection of GrantedAuthority objects.
     */
    public static Collection<GrantedAuthority> extractResourceRoles(Map<String, Object> claims, String resourceClientId) {

        LOGGER.info(claims.toString());

        // Extract realm roles
        Stream<String> realmRoles = extractRolesFromPath(claims, REALM_ACCESS);

        // Extract client-specific roles
        Stream<String> clientRoles = Stream.empty();
        if (resourceClientId != null && claims.containsKey(RESOURCE_ACCESS)) {
            Map<String, Object> resourceAccess = (Map<String, Object>) claims.get(RESOURCE_ACCESS);
            if (resourceAccess.containsKey(resourceClientId)) {
                clientRoles = extractRolesFromPath((Map<String, Object>) resourceAccess.get(resourceClientId), null);
            }
        }

        // Combine, add ROLE_ prefix, and map to authorities
        return Stream.concat(realmRoles, clientRoles)
                .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role.toUpperCase()))
                .collect(Collectors.toSet());
    }

    /**
     * Extracts roles from a specific path in the claims map.
     * @param claims The claims map.
     * @param path The path to the roles.
     * @return A stream of roles.
     */
    @SuppressWarnings("unchecked")
    private static Stream<String> extractRolesFromPath(Map<String, Object> claims, String path) {
        if (path == null || path.isEmpty()) {
            Map<String, Object> rolesMap = claims;
            if (rolesMap != null && rolesMap.containsKey(ROLES)) {
                return ((List<String>) rolesMap.get(ROLES)).stream();
            }
        } else {
            if (claims.containsKey(path)) {
                Map<String, Object> pathMap = (Map<String, Object>) claims.get(path);
                if (pathMap.containsKey(ROLES)) {
                    return ((List<String>) pathMap.get(ROLES)).stream();
                }
            }
        }
        return Stream.empty();
    }
}