package com.security.component;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定义过滤器
 */
@Component
public class VerifyCodeFilter extends GenericFilterBean {

    private String defaultFilterProcessUrl = "doLogin";

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        //当请求方法是POST，并且请求地址是 /doLogin时
        if ("POST".equalsIgnoreCase(request.getMethod()) && defaultFilterProcessUrl.equals(request.getServletPath())){
            //数据验证
            //获取参数中的code字段值，该字段保存了用户从前端页面传来的验证码
            String requestCaptcha = request.getParameter("code");
            //获取session中保存的验证码
            String genCaptcha = (String) request.getSession().getAttribute("index_code");
            //如果用户没有传来验证码，则抛出验证码不能为空异常
            if (StringUtils.isEmpty(requestCaptcha)){
                throw new AuthenticationServiceException("验证码不能为空！");
            }
            //如果用户传入了验证码，则判断验证码是否正确，如果不正确则抛出异常
            if (!genCaptcha.toLowerCase().equals(requestCaptcha.toLowerCase())){
                throw new AuthenticationServiceException("验证码错误！");
            }
        }
        //否则执行 chain.doFilter(request,response);使请求继续向下走。
        filterChain.doFilter(request, response);
    }
}
