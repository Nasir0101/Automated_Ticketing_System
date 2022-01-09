package com.example.automatedticketingsystem.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {


    @GetMapping("/admin")
    public String AdminUser() {
        return "Admin User Logged in";
    }

    @GetMapping("/customer")
    public String CustomerUser() {
        return "Customer User Logged in";
    }


}
