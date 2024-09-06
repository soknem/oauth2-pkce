package com.oauth.resource_server.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api")
@RestController
public class PrivateController {


    @GetMapping("/private")
    @PreAuthorize("hasAnyAuthority('SCOPE_openid')")
    public String privateEndpoint() {
        return "This is a private endpoint, accessible only with a valid token";
    }
}