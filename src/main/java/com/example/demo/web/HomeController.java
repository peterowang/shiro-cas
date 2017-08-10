package com.example.demo.web;

import com.example.demo.config.ExceptionResolver.IncorrectCaptchaException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Created by BFD-593 on 2017/8/8.
 */
@Controller
public class HomeController {
    private static final Logger log = LoggerFactory.getLogger(HomeController.class);
    @RequestMapping({"/","/index"})
    public String index() {
        return "index";
    }


    /**
     * 因为设置了setLoginUrl("/login");登录url如果没有登录，
     * 所有的请求都发送到这里。shiro会自动调用securityManager
     * 此方法不处理登录成功,由shiro进行处理。
     * @param request
     * @param map
     * @return
     * @throws Exception
     */
    @RequestMapping("/login")
    public String login(HttpServletRequest request, Map<String, Object> map) throws Exception {
        // 登录失败从request中获取shiro处理的异常信息。
        // shiroLoginFailure:就是shiro异常类的全类名.
        Object obj = request.getAttribute("shiroLoginFailure");
        log.info("异常信息:"+obj);
        String error = null;
        if( UnknownAccountException.class.isInstance(obj)) {
            error = "用户名/密码错误";
        } else if(IncorrectCredentialsException.class.isInstance(obj)) {
            error = "用户名/密码错误";
        } else if(IncorrectCaptchaException.class.isInstance(obj)){
            error = "验证码错误";
        } else if(obj!=null) {
            error = "其他错误：" + obj;
        }
        map.put("msg", error);
        return "login";
    }
}
