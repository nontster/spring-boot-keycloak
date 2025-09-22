package com.n12g.demo.keycloak;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;
import java.util.stream.Collectors;

@Controller
public class WebController {
    @GetMapping("/")
    public String getIndex() {
        return "index"; // ชี้ไปที่ templates/index.html
    }

    @GetMapping("/profile")
    public String getProfile() {
        return "profile"; // ชี้ไปที่ templates/profile.html
    }
}
