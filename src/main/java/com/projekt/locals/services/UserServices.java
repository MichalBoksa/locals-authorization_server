package com.projekt.locals.services;

import com.projekt.locals.entities.Role;
import com.projekt.locals.entities.User;
import com.projekt.locals.repositories.RoleRepository;
import com.projekt.locals.repositories.UserRepository;
import com.projekt.locals.security.SecurityUser;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.Set;

@Service
@AllArgsConstructor
public class UserServices implements UserDetailsService {

   // private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var user = userRepository.findUserByEmail(username);
        return user.map(SecurityUser::new)
                .orElseThrow(() -> new UsernameNotFoundException("Username with email" + username + "doesn't exists"));
    }

    @Transactional
    //TODO mess with password encoder
    public void signUpUser(User u) {
        if (userRepository.findUserByEmail(u.getEmail()).isPresent())
            throw new UsernameNotFoundException("User with this email already exists");
        //PasswordEncoder ps = passwordEncoder();
//        u.setPassword(ps.encode(u.getPassword()));
        userRepository.save(u);
    }

    public void updateToGuide(String email) {
        User user = userRepository.findUserByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Username with email" + email + "doesn't exists"));
        Role role = roleRepository.findRoleByName("GUIDE")
                .orElseThrow(() -> new RuntimeException(""));
        user.getRoles().clear();
        user.getRoles().add(role);
        userRepository.save(user);
    }

    public void deleteUser(String email) {
        User user = userRepository.findUserByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Username with email" + email + "doesn't exists"));
        userRepository.delete(user);
    }

    public User getUser(String email) {
        User user = userRepository.findUserByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Username with email" + email + "doesn't exists"));
        return user;
    }

    public void updateImage(String email, String image) {
        User user = userRepository.findUserByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Username with email" + email + "doesn't exists"));
        user.setImageUri(image);
        userRepository.save(user);
    }

    public void updateEmail(String email, String newEmail) {
        User user = userRepository.findUserByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Username with email" + email + "doesn't exists"));
        newEmail = newEmail.substring(1,newEmail.length()-1);
        user.setEmail(newEmail);
        userRepository.save(user);
    }

    public void updatePhone(String email, String phone) {
        User user = userRepository.findUserByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Username with email" + email + "doesn't exists"));
        phone = phone.substring(1,phone.length()-1);
        user.setPhoneNumber(phone);
        userRepository.save(user);
    }

}
