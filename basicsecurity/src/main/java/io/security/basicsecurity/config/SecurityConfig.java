package io.security.basicsecurity.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;


@Configuration
@EnableWebSecurity
public class  SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize ->
                        authorize
                                .anyRequest().authenticated()
                )
                .formLogin(form ->
                        form
                                .loginPage("/loginPage")
                                .defaultSuccessUrl("/")
                                .failureUrl("/login")
                                .usernameParameter("uid")
                                .passwordParameter("pwd")
                                .loginProcessingUrl("/login_proc")
                                .successHandler(new AuthenticationSuccessHandler() {
                                    @Override
                                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                        System.out.println("authentication "+ authentication.getName());
                                        response.sendRedirect("/");
                                    }
                                })
                                .failureHandler(new AuthenticationFailureHandler() {
                                    @Override
                                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                        System.out.println("exception"+ exception.getMessage());
                                        response.sendRedirect("/login");
                                    }
                                })
                                .permitAll()
                );
        return http.build();
    }


}
