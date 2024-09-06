package com.oauth.resource_server.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/public")
public class ApiController {

    @GetMapping("")
    public String publicEndpoint() {
        return "This is a public endpoint";
    }
}
