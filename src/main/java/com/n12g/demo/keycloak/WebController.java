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

/**
 * This is a controller that handles the web UI.
 * It provides two endpoints:
 * - /: the home page
 * - /profile: the user profile page
 */
@Controller
public class WebController {
    private static final Logger LOGGER = LoggerFactory.getLogger(WebController.class);

    /**
     * This endpoint returns the home page.
     * @return The name of the view to render.
     */
    @GetMapping("/")
    public String getIndex() {
        return "index"; // templates/index.html
    }

    /**
     * This endpoint returns the user profile page.
     * It retrieves the user's information from the OIDC principal and adds it to the model.
     * @param model The model to add the user's information to.
     * @param principal The OIDC principal of the authenticated user.
     * @return The name of the view to render.
     */
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