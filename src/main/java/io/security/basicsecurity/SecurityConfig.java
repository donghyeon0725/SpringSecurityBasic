package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 정책
        http
                // 요청에 대한 보안 검사 기능을 시작
                .authorizeRequests()
                // 어떤 요청에도 인증을 요구
                .anyRequest().authenticated();

        // 인증 정책
        http
                .formLogin()
                // 사용자 정의 로그인 페이지 => 이 컨트롤러의 이동이 있는지 확인하기
                // .loginPage("/loginPage")
                // 로그인 성공했을 떄
                .defaultSuccessUrl("/")
                // 실패했을 때
                .failureUrl("/login")
                // 사용자 id
                .usernameParameter("userId")
                // password
                .passwordParameter("passwd")
                // 로그인 Form action url => 이는 security 에서 기본 설정으로 /login_proc mapping을 가지고 있게 하고, 이 url을 통해서 인증 요청을 처리하고 있다.
                .loginProcessingUrl("/login_proc")
                // 위 url에서 인증에 성공했을 때 호출, AuthenticationSuccessHandler interface 를 구현한 핸들러를 등록
                /*.successHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    System.out.println("authentication : " + authentication.getName());
                    httpServletResponse.sendRedirect("/");
                })
                // 위 url에서 자격 증명에 실패 했을 때 호출
                .failureHandler((httpServletRequest, httpServletResponse, e) -> {
                    System.out.println("exception : " + e.getMessage());
                    httpServletResponse.sendRedirect("/login");
                })*/
                // 인증을 위한 자원에 대해서는 모든 요청을 허용한다.
                .permitAll()
        ;

        // 로그아웃
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                // LogoutHandler interface를 구현하여야 한다.
                .addLogoutHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    HttpSession session = httpServletRequest.getSession();
                    session.invalidate();
                })
                // LogoutSuccessHandler interface 구현체
                .logoutSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    httpServletResponse.sendRedirect("/login");
                })
                .deleteCookies("remember-me")
        ;

        // remember me 기능
        http
                .rememberMe()
                .rememberMeParameter("/remember")
                .tokenValiditySeconds(3600)
                .userDetailsService(userDetailsService)
        ;
    }
}
