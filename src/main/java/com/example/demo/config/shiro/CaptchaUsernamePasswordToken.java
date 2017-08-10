package com.example.demo.config.shiro;

import org.apache.shiro.authc.UsernamePasswordToken;

/**
 * 对UsernamePasswordToken进行二次封装，将验证码加入
 * Created by BFD-593 on 2017/8/10.
 */
public class CaptchaUsernamePasswordToken extends UsernamePasswordToken {
    /*
    * serialVersionUID用来作为Java对象序列化中的版本标示之用；
    * 如果一个序列化类没有声明这样一个static final的常量，
    * JVM会根据各种参数为这个类计算一个； 对于同样一个类，
    * 不同版本的JDK可能会得出不同的serivalVersionUID;
    * 所以为了兼容性，一般自己加一个，至于值自己定就行，不一定是1L。自己练习的时候加不加没什么区别。
    *
    * */
    private static final long serivalVersionUID = 1L;

    //验证码字符串
    private String captcha;
    public CaptchaUsernamePasswordToken(String username, char[] password, boolean rememberMe, String host, String captcha) {
        super(username,password,rememberMe, host);
        this.captcha = captcha;
    }
    public static long getSerivalVersionUID() {
        return serivalVersionUID;
    }

    public String getCaptcha() {
        return captcha;
    }

    public void setCaptcha(String captcha) {
        this.captcha = captcha;
    }

}
