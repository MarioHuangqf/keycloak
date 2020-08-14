package com.example.keycloak.controller;

import com.example.keycloak.util.KeycloakContext;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.RealmRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

@Controller
public class HomeController {

    @Autowired
    private KeycloakRestTemplate template;

    private String endPoint = "";

    // 公开页
    @GetMapping("/")
    public String index() {
        return "external";
    }

    // 权限页
    @GetMapping("/customers")
    public String customers(Principal principal, Model model) {
        System.out.println(KeycloakContext.getUsername().get());
        System.out.println(KeycloakContext.getAccessToken().get());
        model.addAttribute("username", principal.getName());
        return "customers";
    }

    // 登出
    @GetMapping("/logout")
    public String logout(HttpServletRequest request) throws ServletException {
        request.logout();
        return "redirect:/";
    }

    // 后端服务器通信
    @GetMapping("/toClient")
    @ResponseBody
    public String clientToClient() {
        ResponseEntity<String> message = template.getForEntity(endPoint, String.class);
        return message.getBody();
    }

    @PostMapping("/createUser")
    @ResponseBody
    public void createUser() {
//        Keycloak keycloak = Keycloak.getInstance(
//                "http://localhost:8080/auth",
//                "master",
//                "admin",
//                "password",
//                "admin-cli");
//        RealmRepresentation realm = keycloak.realm("master").toRepresentation();
    }

    // 私有方法
    public KeycloakPrincipal getKeycloakPrinciple(HttpServletRequest request){
        KeycloakPrincipal keycloakPrincipal = (KeycloakPrincipal)request.getUserPrincipal();
        return keycloakPrincipal;
    }

    public String getTokenString(HttpServletRequest request){
        String tokenString = getKeycloakPrinciple(request).getKeycloakSecurityContext().getTokenString();
        return tokenString;
    }
}
