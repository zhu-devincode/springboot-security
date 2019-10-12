package com.security.config;

import com.security.component.VerifyCodeFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    VerifyCodeFilter verifyCodeFilter;

    /*@Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        //下面这两行配置表示在内存中配置了两个用户
        auth.inMemoryAuthentication()
                .withUser("admin").roles("admin").password("$2a$10$OR3VSksVAmCzc.7WeaRPR.t0wyCsIj24k0Bne8iKWV1o.V9wsP8Xe")
                .and()
                .withUser("jack").roles("user").password("$2a$10$OR3VSksVAmCzc.7WeaRPR.t0wyCsIj24k0Bne8iKWV1o.V9wsP8Xe");
    }*/

   /* @Override
    public void configure(WebSecurity web) throws Exception {
        //忽略拦截 直接过滤掉该地址，即该地址不走 Spring Security 过滤器链
        web.ignoring().antMatchers("/vercode");
    }*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(verifyCodeFilter, UsernamePasswordAuthenticationFilter.class);
        //开启登入配置
        http.authorizeRequests()
         // 表示访问 /hello 这个接口，需要具备 admin 这个角色
        .antMatchers("/hello").hasRole("admin")
         //表示剩余的其他接口，登入之后就能访问
        .anyRequest().authenticated()
        .and()
                .formLogin()
                //定义登入页面，未登入时，访问一个需要登入之后的才能访问的接口，会自动跳转到该页面
                //.loginPage("/login_p")
                //登入处理接口
                .loginProcessingUrl("/doLogin")
                //定义登入时，用户名的key，默认为username
                .usernameParameter("username")
                //定义登入时，用户密码的key，默认为password
                .passwordParameter("password")
                //登入成功时的处理器
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        //设置响应类型
                        httpServletResponse.setContentType("application/json;charset=uft-8");
                        PrintWriter printWriter = httpServletResponse.getWriter();
                        printWriter.write("success");
                        printWriter.flush();

                    }
                })
                //登入失败时处理器
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        httpServletResponse.setContentType("application/json;charset=utf-8");
                        PrintWriter printWriter = httpServletResponse.getWriter();
                        printWriter.write("failure");
                        printWriter.flush();
                    }
                })
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/logout")
                //登出成功时处理器
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.setContentType("application/json;charset=utf-8");
                        PrintWriter printWriter = httpServletResponse.getWriter();
                        printWriter.write("logout success");
                        printWriter.flush();
                    }
                })
                .permitAll()
                .and()
                .httpBasic()
                .and()
                .csrf().disable();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        //BCryptPasswordEncoder密码编码工具，可以非常方便的实现密码的加密加盐，相同明文加密出来的结果总是不同，这样就不需要用户去额外保存 盐的字段了，这一点比 Shiro 要方便很多
        return new BCryptPasswordEncoder();
    }
}
