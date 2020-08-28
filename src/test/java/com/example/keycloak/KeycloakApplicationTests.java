package com.example.keycloak;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.lang.reflect.Parameter;
import java.util.regex.Pattern;

@SpringBootTest
class KeycloakApplicationTests {

    @Test
    void contextLoads() {
        boolean a = Pattern.matches("[A-Za-z0-9]{8,16}", "user123");
        System.out.println(a);
    }

}
