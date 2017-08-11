package com.example.demo.web;

import com.example.demo.config.shiro.ShiroConfiguration;
import com.example.demo.model.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpSession;

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
     * shiroFilterFactoryBean.setLoginUrl(loginUrl);我们设置了登录地址，但没设置logout,
     * 所以加一个logout的请求，转到cas的logout上
     * @return
     */
    @RequestMapping(value = "logout", method = { RequestMethod.GET,
            RequestMethod.POST })
    public String loginout()
    {
        return "redirect:"+ShiroConfiguration.logoutUrl;
    }
    @RequestMapping("/403")
    public String fail(){
            return "403";
    }
}
