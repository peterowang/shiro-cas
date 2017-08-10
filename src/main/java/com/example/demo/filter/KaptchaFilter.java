package com.example.demo.filter;

import com.example.demo.config.ExceptionResolver.IncorrectCaptchaException;
import com.example.demo.config.shiro.CaptchaUsernamePasswordToken;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * 对FormAuthenticationFilter进行封装
 * 这里实现验证码校验的思路是自己添加一个Filter继承FormAuthenticationFilter，
 * FormAuthenticationFilter负责表单验证，
 * shiro会先在FormAuthenticationFilter子类去校验验证码，然后再去做身份验证。
 * Created by BFD-593 on 2017/8/10.
 */
public class KaptchaFilter extends FormAuthenticationFilter{

        public static final String DEFAULT_CAPTCHA_PARAM = "captcha";//此处的值应和前台验证码值的name对应

        private String captchaParam = DEFAULT_CAPTCHA_PARAM;

        @Override
        protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {

            CaptchaUsernamePasswordToken token = createToken(request, response);
            try {
                doCaptchaValidate((HttpServletRequest) request, token);//先做校验验证码是否正确
                Subject subject = getSubject(request, response);
                subject.login(token);//身份验证
                return onLoginSuccess(token, subject, request, response);//设置成功跳转
            } catch (AuthenticationException e) {
                return onLoginFailure(token,e,request,response);//设置保存异常对象
            }
        }

        //验证码校验
        protected void doCaptchaValidate(HttpServletRequest request, CaptchaUsernamePasswordToken token) {

            // 从session中获取图形吗字符串,这个是由goggle的框架帮我们设置到session中的
            String captcha = (String) request.getSession().getAttribute(com.google.code.kaptcha.Constants.KAPTCHA_SESSION_KEY);

            // 校验
            if (captcha == null || !captcha.equals(token.getCaptcha())) {
                throw new IncorrectCaptchaException();
            }
        }
        /*
        * 将username password host rememberMe 和captcha封装到我们自己的CaptchaUsernamePasswordToken中
        * */
        @Override
        protected CaptchaUsernamePasswordToken createToken(ServletRequest request, ServletResponse response) {

            String username = getUsername(request);
            String password = getPassword(request);
            String host = getHost(request);
            boolean rememberMe = isRememberMe(request);
            String captcha = getCaptcha(request);
            return new CaptchaUsernamePasswordToken(username,password.toCharArray(),rememberMe,host,captcha);
        }
        /*
        * 在request请求中获取name=captcha的值（也就是验证码的值）
        * */
        protected  String getCaptcha(ServletRequest request) {
            return WebUtils.getCleanParam(request, getCaptchaParam());
        }

        //保存异常对象到request
        @Override
        protected void setFailureAttribute(ServletRequest request, org.apache.shiro.authc.AuthenticationException ae) {
            request.setAttribute(getFailureKeyAttribute(), ae);
        }

        public String getCaptchaParam() {
            return captchaParam;
        }

        public void setCaptchaParam(String captchaParam) {
            this.captchaParam = captchaParam;
        }

}
