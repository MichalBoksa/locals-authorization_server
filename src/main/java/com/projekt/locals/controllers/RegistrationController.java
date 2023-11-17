package com.projekt.locals.controllers;

import com.projekt.locals.entities.User;
import com.projekt.locals.repositories.UserRepository;
import com.projekt.locals.services.UserServices;
import lombok.AllArgsConstructor;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Controller
@AllArgsConstructor
@EnableWebSecurity
public class RegistrationController {

    private UserServices userServices;
    private UserRepository userRepository;

    @GetMapping("/users/getUser/{email}")
    public Optional<User> getUser(@PathVariable String email) {
        return userRepository.findUserByEmail(email);
    }


    @GetMapping(value="/login")
    public String login() {
        return "login";
    }

    @GetMapping(value="/register_form")
    public String register(Model model) {
        model.addAttribute("user",new User());
        return "register_form";
    }
    //TODO maybe add http status in return
    @PostMapping("/register/save")
    public String signUp (@ModelAttribute User user) {
        userServices.signUpUser(user);
        return "register_form";
    }


//    @PostMapping("/signIn")
//    public void SignIn()

//        //TODO changerequestbody to pathrequest
//    @PostMapping("/updatePassword")
//    public void updateUser (@RequestBody int id, @RequestBody String value) {
//        userServices.updatePassword(id,value);
//    }
}
