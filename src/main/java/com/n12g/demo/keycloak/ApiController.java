package com.n12g.demo.keycloak;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * This is a REST controller that provides two endpoints:
 * - /api/user/data: accessible by users with the USER role
 * - /api/admin/data: accessible by users with the ADMIN role
 */
@RestController
@RequestMapping("/api")
public class ApiController {
    private static final Logger LOGGER = LoggerFactory.getLogger(ApiController.class);

    /**
     * This endpoint is accessible by users with the USER role.
     * @return A string indicating that this is user data.
     */
    @GetMapping("/user/data")
    public String getUserData() {
        return "This is user data, accessible by USER role.";
    }

    /**
     * This endpoint is accessible by users with the ADMIN role.
     * @return A string indicating that this is admin data.
     */
    @GetMapping("/admin/data")
    public String getAdminData() {
        return "This is admin data, accessible by ADMIN role.";
    }

}