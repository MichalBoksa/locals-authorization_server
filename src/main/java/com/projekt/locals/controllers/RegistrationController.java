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

public class RegistrationController {

    private UserServices userServices;
    private UserRepository userRepository;

    @GetMapping(path = "/users/getUser/{email}")
    @ResponseBody
    public User getUser(@PathVariable String email) {
       return userServices.getUser(email);
       // return userRepository.findUserByEmail(email);
    }

    @GetMapping(path = "/users/getUserById/{id}")
    @ResponseBody
    public Optional<User> getUserById(@PathVariable int id) {
        return userRepository.findUserById(id);
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
        return "login";
    }

    @PutMapping("/updateToGuide/{email}")
    @ResponseBody
    public void updateToGuide (@PathVariable String email) {
        userServices.updateToGuide(email);
    }

    @DeleteMapping("/deleteUser/{email}")
    @ResponseBody
    public void deleteUser(@PathVariable String email){userServices.deleteUser(email);}

    @PutMapping("/users/updateImage/{email}")
    @ResponseBody
    public void updateImage(@PathVariable String email, @RequestBody String image) {
       userServices.updateImage(email, image);
    }

    @PutMapping("/users/updateEmail/{email}")
    @ResponseBody
    public void updateEmail(@PathVariable String email, @RequestBody String newEmail) {
        userServices.updateEmail(email, newEmail);
    }

    @PutMapping("/users/updatePhone/{email}")
    @ResponseBody
    public void updatePhone(@PathVariable String email, @RequestBody String phone) {
        userServices.updatePhone(email, phone);
    }


}
