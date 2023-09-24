package com.projekt.locals.controllers;

import com.projekt.locals.entities.User;
import com.projekt.locals.repositories.UserRepository;
import com.projekt.locals.services.UserServices;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@AllArgsConstructor
public class RegistrationController {

    private UserServices userServices;
    private UserRepository userRepository;

    //TODO test use, delete later
    @GetMapping("/users/getUser/{email}")
    public Optional<User> getAllUsers(@PathVariable String email) {
        return userRepository.findUserByEmail(email);
    }

    //TODO maybe add http status in return
    @PostMapping("/signUp")
    public void signUp (@RequestBody User u) {
        userServices.signUpUser(u);
    }

    @GetMapping("/hello")
    public String hello() {
        return "HELLO";
    }


//    @PostMapping("/signIn")
//    public void SignIn()

//        //TODO changerequestbody to pathrequest
//    @PostMapping("/updatePassword")
//    public void updateUser (@RequestBody int id, @RequestBody String value) {
//        userServices.updatePassword(id,value);
//    }
}
