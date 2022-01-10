package com.example.automatedticketingsystem.securityConfig;

import com.example.automatedticketingsystem.repository.UserRepository;
import com.example.automatedticketingsystem.securityConfig.filter.AuthenticationFilter;
import com.example.automatedticketingsystem.securityConfig.filter.AuthorizationFilter;
import com.example.automatedticketingsystem.service.Implementations.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.List;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private UserRepository userRepository;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable().authorizeRequests()
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilter(new AuthenticationFilter(authenticationManager()))
                .addFilter(new AuthorizationFilter(authenticationManager(),userRepository))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.headers().frameOptions().disable();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        List<String> DEFAULT_PERMIT_ALL = new ArrayList<>();
        DEFAULT_PERMIT_ALL.add("*");
        List<String> DEFAULT_PERMIT_HEADER = new ArrayList<>();
        DEFAULT_PERMIT_HEADER.add("Authorization");
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(DEFAULT_PERMIT_ALL);
        configuration.setAllowedMethods(DEFAULT_PERMIT_ALL);
        configuration.setAllowedHeaders(DEFAULT_PERMIT_ALL);
        configuration.setMaxAge(1800L);
        configuration.setExposedHeaders(DEFAULT_PERMIT_HEADER);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
