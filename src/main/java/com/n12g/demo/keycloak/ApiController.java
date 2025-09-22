package com.n12g.demo.keycloak;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ApiController {
    @GetMapping("/user/data")
    public String getUserData() {
        return "This is user data, accessible by USER role.";
    }

    @GetMapping("/admin/data")
    public String getAdminData() {
        return "This is admin data, accessible by ADMIN role.";
    }

    @GetMapping("/profile")
    public java.util.Map<String, Object> getProfile(@org.springframework.security.core.annotation.AuthenticationPrincipal org.springframework.security.oauth2.core.oidc.user.OidcUser principal) {
        java.util.Map<String, Object> profile = new java.util.HashMap<>();
        profile.put("username", principal.getAttribute("preferred_username"));
        profile.put("email", principal.getAttribute("email"));
        profile.put("roles", principal.getAuthorities().stream()
                .map(org.springframework.security.core.GrantedAuthority::getAuthority)
                .map(role -> role.replace("ROLE_", ""))
                .collect(java.util.stream.Collectors.toList()));
        return profile;
    }
}
