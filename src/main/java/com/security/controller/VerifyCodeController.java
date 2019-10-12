package com.security.controller;

import com.security.util.VerifyCode;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.image.BufferedImage;
import java.io.IOException;

@RestController
public class VerifyCodeController {

    /**
     * 验证码接口
     * @param request
     * @param response
     * @throws IOException
     */
    @GetMapping("/vercode")
    public void code(HttpServletRequest request, HttpServletResponse response) throws IOException {
        VerifyCode vc = new VerifyCode();
        BufferedImage image = vc.getImage();
        String text = vc.getText();
        HttpSession session = request.getSession();
        session.setAttribute("index_code", text);
        VerifyCode.output(image, response.getOutputStream());
    }
}
