package com.example.automatedticketingsystem.filter;

import com.example.automatedticketingsystem.common.util.JwtUtil;
import com.example.automatedticketingsystem.requestModel.LoginModel;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;

import static com.example.automatedticketingsystem.common.constant.SecurityConstants.HEADER_STRING;
import static com.example.automatedticketingsystem.common.constant.SecurityConstants.TOKEN_PREFIX;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    public AuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        try {
            LoginModel creds = new ObjectMapper()
                    .readValue(req.getInputStream(), LoginModel.class);

            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            creds.getUserName(),
                            creds.getPassword(),
                            new ArrayList<>())
            );
        } catch (BadCredentialsException ex) {
            throw new BadCredentialsException(ex.getMessage());
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain, Authentication auth) {
        String userName = ((User) auth.getPrincipal()).getUsername();
        String claim = String.valueOf(auth.getAuthorities().toArray()[0]);
        String token = JwtUtil.generateToken(userName, claim);
        res.addHeader(HEADER_STRING, TOKEN_PREFIX + token);
    }


}
