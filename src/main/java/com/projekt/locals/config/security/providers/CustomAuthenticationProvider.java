package com.projekt.locals.config.security.providers;

import com.projekt.locals.config.security.authentication.CustomAuthentication;
import com.projekt.locals.entities.User;
import com.projekt.locals.services.UserServices;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserServices userServices;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomAuthentication customAuthentication = (CustomAuthentication) authentication;

        User user = customAuthentication.getUser();
        UserDetails DBUserDetails = userServices.loadUserByUsername(user.getEmail());
        //TODO add bcrypt decoding
        if(DBUserDetails != null
                && userServices.loadUserByUsername(user.getEmail()).getPassword().equals(user.getPassword())) {
            return new CustomAuthentication(true,user);
        }
        throw new BadCredentialsException("Wrong creditials");
    }

    @Override
    public boolean supports(Class<?> authentication) {

        return CustomAuthentication.class.equals(authentication);
    }
}
