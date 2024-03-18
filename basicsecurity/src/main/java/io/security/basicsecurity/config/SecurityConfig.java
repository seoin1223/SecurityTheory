package io.security.basicsecurity.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;
import java.util.logging.Handler;


@Configuration
@EnableWebSecurity
public class  SecurityConfig {

    @Autowired
    UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http

                .authorizeHttpRequests(authorize ->
                        authorize
                                .anyRequest().authenticated()
                )
                .formLogin(form ->
                        form
//                                .loginPage("/login")
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
                )
                .logout(logout ->
                        logout
                                .logoutUrl("/logout")
                                .logoutSuccessUrl("/login")
                                .addLogoutHandler(new LogoutHandler() {
                                    @Override
                                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                                        HttpSession session = request.getSession();
                                        session.invalidate();
                                    }
                                })
                                .logoutSuccessHandler(new LogoutSuccessHandler() {
                                    @Override
                                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                        response.sendRedirect("/login");
                                    }
                                })
                                .deleteCookies("remeber-me")
                )
                .rememberMe( me ->
                        me
                                .rememberMeParameter("remember") // 기본 파라미터명은 remember-me인데 remember로 변경
                                .tokenValiditySeconds(3600) // 1시간으로 변경 -> default 는 14일
                                .alwaysRemember(false) // ture면 기능이 활성화되지 않아도 항상 실행 -> 기본 false
                                .userDetailsService(userDetailsService)// 계정을 조회하는 class
                )



        ;
        return http.build();
    }


}


