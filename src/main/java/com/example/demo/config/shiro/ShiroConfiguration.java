package com.example.demo.config.shiro;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
import com.example.demo.filter.KaptchaFilter;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.handler.SimpleMappingExceptionResolver;

import javax.servlet.Filter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * shiro配置类
 * Created by BFD-593 on 2017/8/8.
 */
@Configuration
public class ShiroConfiguration {
    @Bean(name="shiroFilter")
    public ShiroFilterFactoryBean shiroFilterFactoryBean(@Qualifier("securityManager") SecurityManager manager) {
        //设置shiro安全管理框架
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(manager);
        //将我们自己的拦截器注入到shiro中
        Map<String, Filter> filterMap = shiroFilterFactoryBean.getFilters();//先获取shiro内部拦截器
        KaptchaFilter kaptchaFilter = new KaptchaFilter();//初始化自己的拦截器
        filterMap.put("kaptchaFilter", kaptchaFilter);//加入我们的拦截器
        shiroFilterFactoryBean.setFilters(filterMap);//注入

        //配置记住我或认证通过可以访问的地址
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        filterChainDefinitionMap.put("/", "user");
        filterChainDefinitionMap.put("/index", "user");
        /** authc：该过滤器下的页面必须验证后才能访问，它是Shiro内置的一个拦截器
         * org.apache.shiro.web.filter.authc.FormAuthenticationFilter */
        // anon：它对应的过滤器里面是空的,什么都没做,可以理解为不拦截
        filterChainDefinitionMap.put("/logout", "logout");
        filterChainDefinitionMap.put("/favicon.ico", "anon");
        filterChainDefinitionMap.put("/static/**", "anon");

        filterChainDefinitionMap.put("/login", "kaptchaFilter");//设置登录时使用kaptchaFilter我们自己的拦截器
        filterChainDefinitionMap.put("/kaptcha.jpg", "anon");//图片验证码(kaptcha框架,会访问localhost:8080/kaptcha.jpg来自动生成验证码)

        filterChainDefinitionMap.put("/**", "authc");
        //authc表示需要验证身份才能访问，还有一些比如anon表示不需要验证身份就能访问等。
        //关于为什么设置filterChainDefinitionMap.put("/favicon.ico", "anon");，请参考Shiro登录后下载favicon.ico问题

        shiroFilterFactoryBean.setLoginUrl("/login");//登录url
        shiroFilterFactoryBean.setSuccessUrl("/index");//登录成功后跳转的页面

        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }


    /**
     * 不指定名字的话，自动创建一个方法名第一个字母小写的bean
     * @Bean(name = "securityManager")
     * @return
     */
    @Bean(name="securityManager")
    public SecurityManager securityManager(@Qualifier("authRealm") MyShiroRealm authRealm,
                                           @Qualifier("ehCacheManager") EhCacheManager ehCacheManager) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(authRealm);
        securityManager.setCacheManager(ehCacheManager);//注入缓存对象,防止每访问一个带权限的请求都要shiro去查询数据库的权限
        securityManager.setRememberMeManager(rememberMeManager()); //注入记住我cookie管理器(记住密码)
        return securityManager;
    }

    /**
     * Shiro Realm 继承自AuthorizingRealm的自定义Realm,即指定Shiro验证用户登录的类为自定义的
     *
     * @param
     * @return
     */
    @Bean(name="authRealm")
    public MyShiroRealm userRealm(@Qualifier("credentialsMatcher") CredentialsMatcher matcher) {
        MyShiroRealm userRealm = new MyShiroRealm();
        //告诉realm,使用credentialsMatcher加密算法类来验证密文
        userRealm.setCredentialsMatcher(matcher);
        return userRealm;
    }

    /**
     * 密码比较器
     * @return
     */
    @Bean(name="credentialsMatcher")
    public CredentialsMatcher credentialsMatcher() {
        return new CredentialsMatcher();
    }

    /**
     * 权限认证
     * 需要开启Shiro AOP注解支持
     * @RequiresPermissions({"userinfo:view"})
     * @RequiresRoles({"wangjing"})等注解的支持
     * @param securityManager
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager){
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }

    /**
     * 当用户无权限访问403页面而不抛异常，默认shiro会报UnauthorizedException异常
     * @return
     */
    @Bean
    public SimpleMappingExceptionResolver resolver() {
        SimpleMappingExceptionResolver resolver = new SimpleMappingExceptionResolver();
        Properties properties = new Properties();
        properties.setProperty("org.apache.shiro.authz.UnauthorizedException", "/403");
        resolver.setExceptionMappings(properties);
        return resolver;
    }

    /**
     * 整合thymeleaf中可以使用shiro标签
     * @return
     */
    @Bean
    public ShiroDialect shiroDialect() {
        return new ShiroDialect();
    }

    /**
     * shiro缓存对象，防止当每次访问带权限的请求时，shiro都去执行权限认证，进行查询权限
     * 也就是说，只需给shiro一次权限即可（缓存），不需要每次查询权限
     * @return
     */
    @Bean(name="ehCacheManager")
    public EhCacheManager ehCacheManager() {
        EhCacheManager ehCacheManager = new EhCacheManager();
        ehCacheManager.setCacheManagerConfigFile("classpath:config/ehcache-shiro.xml");
        return ehCacheManager;
    }
    /**
     * cookie对象;
     * rememberMeCookie()方法是设置Cookie的生成模版，比如cookie的name，cookie的有效时间等等。
     * @return
     */
    @Bean
    public SimpleCookie rememberMeCookie(){
        //这个参数是cookie的名称，对应前端的checkbox的name = rememberMe
        SimpleCookie simpleCookie = new SimpleCookie("rememberMe");
        //<!-- 记住我cookie生效时间30天 ,单位秒;-->
        simpleCookie.setMaxAge(259200);
        return simpleCookie;
    }
    /**
     * cookie管理对象;
     * rememberMeManager()方法是生成rememberMe管理器，而且要将这个rememberMe管理器设置到securityManager中
     * @return
     */
    @Bean
    public CookieRememberMeManager rememberMeManager(){
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
        cookieRememberMeManager.setCookie(rememberMeCookie());
        //rememberMe cookie加密的密钥 建议每个项目都不一样 默认AES算法 密钥长度(128 256 512 位)
        cookieRememberMeManager.setCipherKey(Base64.decode("2AvVhdsgUs0FSA3SDFAdag=="));
        return cookieRememberMeManager;
    }
}
