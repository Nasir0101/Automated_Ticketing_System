package com.example.automatedticketingsystem.securityConfig.filter;

import com.example.automatedticketingsystem.entity.UserModel;
import com.example.automatedticketingsystem.repository.UserRepository;
import com.example.automatedticketingsystem.securityConfig.constant.SecurityConstants;
import com.example.automatedticketingsystem.securityConfig.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

public class AuthorizationFilter extends BasicAuthenticationFilter {

    @Autowired
    private final UserRepository userRepository;

    public AuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {

        String header = req.getHeader(SecurityConstants.HEADER_STRING);

        if (header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(SecurityConstants.HEADER_STRING);
        if (token != null) {
            token = token.replace(SecurityConstants.TOKEN_PREFIX, "");
            String userName = JwtUtil.extractUsername(token);
            Boolean isExpired = JwtUtil.isTokenExpired(token);
            List<SimpleGrantedAuthority> authorities = JwtUtil.extractRole(token);
            if (userName != null && !isExpired) {
                UserModel userModel = userRepository.findByUserName(userName);
                if (userModel == null) return null;
                return new UsernamePasswordAuthenticationToken(userModel, null, authorities);
            }
        }
        return null;
    }
}
