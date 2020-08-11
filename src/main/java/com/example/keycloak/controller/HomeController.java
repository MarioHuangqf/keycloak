package com.example.keycloak.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

@Controller
public class HomeController {

    // 公开页
    @GetMapping("/")
    public String index() {
        return "external";
    }

    // 权限页
    @GetMapping("/customers")
    public String customers(Principal principal, Model model) {
        model.addAttribute("username", principal.getName());
        return "customers";
    }

    // 登出
    @GetMapping("/logout")
    public String logout(HttpServletRequest request) throws ServletException {
        request.logout();
        return "redirect:/";
    }
}
