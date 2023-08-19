package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.model.User;
import java.security.Principal;

@Controller
@RequestMapping("/user")
public class UserController {

    private final UserDetailsService userService;

    @Autowired
    public UserController(UserDetailsService userService) {
        this.userService = userService;
    }

    @GetMapping
    public String welcomeUser(Principal principal, Model model){
        User user = (User) userService.loadUserByUsername(principal.getName());
        model.addAttribute("user", user);
        return "user";
    }
}
