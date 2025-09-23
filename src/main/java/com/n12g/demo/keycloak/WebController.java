package com.n12g.demo.keycloak;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.stream.Collectors;

@Controller
public class WebController {
    @GetMapping("/")
    public String getIndex() {
        return "index"; // templates/index.html
    }

    @GetMapping("/profile")
    public String getProfile(Model model, @AuthenticationPrincipal OidcUser principal) {
        model.addAttribute("username", principal.getAttribute("preferred_username"));
        model.addAttribute("email", principal.getAttribute("email"));
        model.addAttribute("roles", principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(role -> role.replace("ROLE_", ""))
                .collect(Collectors.toList()));
        return "profile"; // templates/profile.html
    }
}
