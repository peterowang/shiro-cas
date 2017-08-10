package com.example.demo.config.ExceptionResolver;


import org.apache.shiro.authc.AuthenticationException;

/**
 * 将shiro异常进行二次封装，抛出该异常表示验证码不正确，好让controller通过判断进行error设置展示在前台
 * Created by BFD-593 on 2017/8/10.
 */
public class IncorrectCaptchaException extends AuthenticationException {
    /*
    * serialVersionUID用来作为Java对象序列化中的版本标示之用；
    * 如果一个序列化类没有声明这样一个static final的常量，
    * JVM会根据各种参数为这个类计算一个； 对于同样一个类，
    * 不同版本的JDK可能会得出不同的serivalVersionUID;
    * 所以为了兼容性，一般自己加一个，至于值自己定就行，不一定是1L。自己练习的时候加不加没什么区别。
    *
    * */
   private static final long serialVersionUID = 1L;

    public IncorrectCaptchaException() {
        super();
    }
    public IncorrectCaptchaException(String message, Throwable cause) {
        super(message, cause);
    }
    public IncorrectCaptchaException(String message) {
        super(message);
    }

    public IncorrectCaptchaException(Throwable cause) {
        super(cause);
    }
}
