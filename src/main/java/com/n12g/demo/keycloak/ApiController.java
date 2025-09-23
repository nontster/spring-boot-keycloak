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

}
