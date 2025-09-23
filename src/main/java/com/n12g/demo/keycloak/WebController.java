package com.n12g.demo.keycloak;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.stream.Collectors;

@Controller
public class WebController {
    private static final Logger LOGGER = LoggerFactory.getLogger(WebController.class);

    @GetMapping("/")
    public String getIndex() {
        return "index"; // templates/index.html
    }

    // @AuthenticationPrincipal annotation tells Spring Security to inject the currently authenticated
    // user's principal into this method. Using the user object, we can retrieve information about the
    // logged on user. In this example, we retrieve the username of the user and his or her email address
    // and roles. We put those as attributes in the Model so we can display them in our Thymeleaf template
    @GetMapping("/profile")
    public String getProfile(Model model, @AuthenticationPrincipal OidcUser principal) {

        LOGGER.info(principal.getIdToken().getClaims().toString());

        model.addAttribute("username", principal.getAttribute("preferred_username"));
        model.addAttribute("email", principal.getAttribute("email"));
        model.addAttribute("roles", principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(role -> role.replace("ROLE_", ""))
                .collect(Collectors.toList()));
        return "profile"; // templates/profile.html
    }
}
