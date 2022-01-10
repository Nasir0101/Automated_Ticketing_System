package com.example.automatedticketingsystem.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {


    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String AdminUser() {
        return "Admin User Logged in";
    }

    @PreAuthorize("hasRole('CUSTOMER')")
    @GetMapping("/customer")
    public String CustomerUser() {
        return "Customer User Logged in";
    }


}
