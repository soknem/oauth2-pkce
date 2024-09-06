package com.oauth.resource_server.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api")
@RestController
public class PrivateController {


    @GetMapping("/private")
    public String privateEndpoint() {
        return "This is a private endpoint, accessible only with a valid token";
    }
}