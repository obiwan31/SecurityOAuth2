package com.example.SecurityOAuth2.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityOAuth2Controller {

    @GetMapping("/")
    public String defaultHomePageMethod() {
        return "hello, you are logged in";
    }

    @GetMapping("/users")
    public String getUsersDetails() {
        return "fetched the details of successfully";
    }
}
