package com.n12g.demo.keycloak;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

// คลาสนี้จะทำหน้าที่อ่าน Roles จาก Claim ใน JWT แล้วแปลงเป็น GrantedAuthority
public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    private final String clientId;

    // ✅ 2. เพิ่ม Constructor เพื่อรับ clientId
    public KeycloakRoleConverter(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        // ✅ 3. เปลี่ยน logic การดึง Role ทั้งหมด
        Map<String, Object> resourceAccess = (Map<String, Object>) jwt.getClaims().get("resource_access");
        if (resourceAccess == null || resourceAccess.isEmpty()) {
            return Collections.emptyList();
        }

        Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(this.clientId);
        if (clientAccess == null || clientAccess.isEmpty()) {
            return Collections.emptyList();
        }

        Collection<String> roles = (Collection<String>) clientAccess.get("roles");
        if (roles == null || roles.isEmpty()) {
            return Collections.emptyList();
        }

        return roles.stream()
                .map(roleName -> "ROLE_" + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

    }
}
