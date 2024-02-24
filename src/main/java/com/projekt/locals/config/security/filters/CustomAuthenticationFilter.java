//CUSTOM SECURITY FILTER NOT NEEDED TO PROJECT RIGHT NOW, BUT FOR SURE INTERESTING



//package com.projekt.locals.config.security.filters;
//
//import com.projekt.locals.config.security.authentication.CustomAuthentication;
//import com.projekt.locals.config.security.managers.CustomAuthenticationManager;
//import lombok.AllArgsConstructor;
//
//import com.projekt.locals.entities.User;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
//@AllArgsConstructor
////@Component
//public class CustomAuthenticationFilter extends OncePerRequestFilter {
//
//    private final CustomAuthenticationManager customAuthenticationManager;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        //TODO check how to change string to user
//        String[] userCredentials = request.getHeader("userCredentials").split(":");
//
//        //TODO change new User
//        var customAuthentication = new CustomAuthentication(false,
//                new User(userCredentials[0],userCredentials[1]));
//        var authenticationResult = customAuthenticationManager.authenticate(customAuthentication);
//
//        if(authenticationResult.isAuthenticated()) {
//            SecurityContextHolder.getContext().setAuthentication(authenticationResult);
//            filterChain.doFilter(request,response);
//        }
//    }
//}
