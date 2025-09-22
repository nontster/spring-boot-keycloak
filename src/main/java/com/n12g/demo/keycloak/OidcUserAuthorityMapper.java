package com.n12g.demo.keycloak;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import java.util.*;
import java.util.stream.Collectors;

public class OidcUserAuthorityMapper implements GrantedAuthoritiesMapper {
    private final String clientId;

    // ✅ 2. เพิ่ม Constructor เพื่อรับ clientId
    public OidcUserAuthorityMapper(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

        authorities.forEach(authority -> {
            mappedAuthorities.add(authority); // ✅ Keep original authorities
            if (authority instanceof OidcUserAuthority) {
                OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) authority;
                Map<String, Object> claims = oidcUserAuthority.getAttributes();

                // ✅ 3. เปลี่ยน logic การดึง Role ทั้งหมด
                Map<String, Object> resourceAccess = (Map<String, Object>) claims.get("resource_access");
                if (resourceAccess != null && resourceAccess.containsKey(this.clientId)) {
                    Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(this.clientId);
                    Collection<String> roles = (Collection<String>) clientAccess.get("roles");

                    if (roles != null && !roles.isEmpty()) {
                        mappedAuthorities.addAll(roles.stream()
                                .map(roleName -> "ROLE_" + roleName)
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList()));
                    }
                }
            }
        });

        return mappedAuthorities;
    }
}
