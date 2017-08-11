package com.example.demo.config.shiro;

import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.cas.CasFilter;
import org.apache.shiro.cas.CasSubjectFactory;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.handler.SimpleMappingExceptionResolver;

import javax.servlet.Filter;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * shiro配置类
 * Created by BFD-593 on 2017/8/8.
 */
@Configuration
public class ShiroConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(ShiroConfiguration.class);
    // cas server地址
    public static final String casServerUrlPrefix = "https://localhost:8443/cas";
    // Cas登录页面地址
    public static final String casLoginUrl = casServerUrlPrefix + "/login";
    // Cas登出页面地址
    public static final String casLogoutUrl = casServerUrlPrefix + "/logout";
    // 当前工程对外提供的服务地址
    public static final String shiroServerUrlPrefix = "http://localhost:8089";
    // casFilter UrlPattern
    public static final String casFilterUrlPattern = "/cas";
    // 登录地址
    public static final String loginUrl = casLoginUrl + "?service=" + shiroServerUrlPrefix + casFilterUrlPattern;
    // 登出地址（casserver启用service跳转功能，需在webapps\cas\WEB-INF\cas.properties文件中启用cas.logout.followServiceRedirects=true）
    public static final String logoutUrl = casLogoutUrl+"?service="+shiroServerUrlPrefix;
    // 登录成功地址
    public static final String loginSuccessUrl = "/index";
    // 权限认证失败跳转地址
    public static final String unauthorizedUrl = "/403";
        @Bean
        public EhCacheManager getEhCacheManager() {
            EhCacheManager em = new EhCacheManager();
            em.setCacheManagerConfigFile("classpath:config/ehcache-shiro.xml");
            return em;
        }

        @Bean(name = "myShiroCasRealm")
        public MyShiroCasRealm myShiroCasRealm(EhCacheManager cacheManager) {
            MyShiroCasRealm realm = new MyShiroCasRealm();
            realm.setCacheManager(cacheManager);
            return realm;
        }

        /**
         * 注册单点登出listener
         * @return
         */
        @Bean
        public ServletListenerRegistrationBean singleSignOutHttpSessionListener(){
            ServletListenerRegistrationBean bean = new ServletListenerRegistrationBean();
            bean.setListener(new SingleSignOutHttpSessionListener());
            bean.setEnabled(true);
            return bean;
        }

        /**
         * 注册单点登出filter
         * @return
         */
        @Bean
        public FilterRegistrationBean singleSignOutFilter(){
            FilterRegistrationBean bean = new FilterRegistrationBean();
            bean.setName("singleSignOutFilter");
            bean.setFilter(new SingleSignOutFilter());
            bean.addUrlPatterns("/*");
            bean.setEnabled(true);
            return bean;
        }



        /**
         * 注册DelegatingFilterProxy（Shiro）
         */
        @Bean
        public FilterRegistrationBean delegatingFilterProxy() {
            FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
            filterRegistration.setFilter(new DelegatingFilterProxy("shiroFilter"));
            //  该值缺省为false,表示生命周期由SpringApplicationContext管理,设置为true则表示由ServletContainer管理
            filterRegistration.addInitParameter("targetFilterLifecycle", "true");
            filterRegistration.setEnabled(true);
            filterRegistration.addUrlPatterns("/*");
            return filterRegistration;
        }


        @Bean(name = "lifecycleBeanPostProcessor")
        public LifecycleBeanPostProcessor getLifecycleBeanPostProcessor() {
            return new LifecycleBeanPostProcessor();
        }

        @Bean
        public DefaultAdvisorAutoProxyCreator getDefaultAdvisorAutoProxyCreator() {
            DefaultAdvisorAutoProxyCreator daap = new DefaultAdvisorAutoProxyCreator();
            daap.setProxyTargetClass(true);
            return daap;
        }

        @Bean(name = "securityManager")
        public DefaultWebSecurityManager getDefaultWebSecurityManager(@Qualifier("myShiroCasRealm") MyShiroCasRealm myShiroCasRealm) {
            DefaultWebSecurityManager dwsm = new DefaultWebSecurityManager();
            dwsm.setRealm(myShiroCasRealm);
            //用户授权/认证信息Cache, 采用EhCache 缓存
            dwsm.setCacheManager(getEhCacheManager());
            // 指定 SubjectFactory
            dwsm.setSubjectFactory(new CasSubjectFactory());
            return dwsm;
        }



        /**
         * CAS过滤器
         *
         * @return
         */
        @Bean(name = "casFilter")
        public CasFilter getCasFilter() {
            CasFilter casFilter = new CasFilter();
            casFilter.setName("casFilter");
            casFilter.setEnabled(true);
            // 登录失败后跳转的URL，也就是 Shiro 执行 CasRealm 的 doGetAuthenticationInfo 方法向CasServer验证tiket
            casFilter.setFailureUrl(loginUrl);// 我们选择认证失败后再打开登录页面
            return casFilter;
        }

        /**
         * ShiroFilter
         * @param securityManager
         * @param casFilter
         * @return
         */
        @Bean(name = "shiroFilter")
        public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("securityManager") DefaultWebSecurityManager securityManager,
                                                                @Qualifier("casFilter") CasFilter casFilter) {
            ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
            // 必须设置 SecurityManager
            shiroFilterFactoryBean.setSecurityManager(securityManager);
            // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
            shiroFilterFactoryBean.setLoginUrl(loginUrl);
            // 登录成功后要跳转的连接
            shiroFilterFactoryBean.setSuccessUrl(loginSuccessUrl);
            shiroFilterFactoryBean.setUnauthorizedUrl(unauthorizedUrl);
            // 添加casFilter到shiroFilter中
            Map<String, Filter> filters = new HashMap<>();
            filters.put("casFilter", casFilter);
            shiroFilterFactoryBean.setFilters(filters);

            loadShiroFilterChain(shiroFilterFactoryBean);
            return shiroFilterFactoryBean;
        }

        /**
         * 加载shiroFilter权限控制规则（从数据库读取然后配置）,角色/权限信息由MyShiroCasRealm对象提供doGetAuthorizationInfo实现获取来的
         */
        private void loadShiroFilterChain(@Qualifier("shiroFilter") ShiroFilterFactoryBean shiroFilterFactoryBean){
            /////////////////////// 下面这些规则配置最好配置到配置文件中 ///////////////////////
            Map<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();

            // authc：该过滤器下的页面必须登录后才能访问，它是Shiro内置的一个拦截器org.apache.shiro.web.filter.authc.FormAuthenticationFilter
            // anon: 可以理解为不拦截
            // user: 登录了就不拦截
            // roles["admin"] 用户拥有admin角色
            // perms["permission1"] 用户拥有permission1权限
            // filter顺序按照定义顺序匹配，匹配到就验证，验证完毕结束。
            // url匹配通配符支持：? * **,分别表示匹配1个，匹配0-n个（不含子路径），匹配下级所有路径

            //1.shiro集成cas后，首先添加该规则
            filterChainDefinitionMap.put(casFilterUrlPattern, "casFilter");

            //2.不拦截的请求
            filterChainDefinitionMap.put("/css/**","anon");
            filterChainDefinitionMap.put("/login", "anon");
            filterChainDefinitionMap.put("/logout","anon");
            filterChainDefinitionMap.put("/error","anon");

            //3.拦截的请求,并且拥有哪些权限才可以访问,当没有权限时
            //  我们通过在shiroFilter里设置 shiroFilterFactoryBean.setUnauthorizedUrl(unauthorizedUrl);
            //  让其跳转到403页面,需要加403的controller请求哦
            //  这里还可以通过另一种方式,就是在controller的需要的请求上,加shiro的权限注解
            //  如果通过注解的方式,则需要通过以下两个配置bean来分别设置支持shiro注解和无权限跳转的页面
            filterChainDefinitionMap.put("/userinfo/userList", "authc,perms[\"userinfo:view\"],roles[\"wangjing\"]"); //需要登录，且用户有权限为userinfo:view并且角色为wangjing
            filterChainDefinitionMap.put("/userinfo/userDel", "authc,perms[\"userinfo:view\"],roles[\"admin\"]");
            filterChainDefinitionMap.put("/userinfo/userAdd", "authc,perms[\"userinfo:view\"],roles[\"redhat\"]");
            //4.登录过的不拦截
            filterChainDefinitionMap.put("/**", "user");
            shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        }
/*
        *//**
         * 权限认证
         * 需要开启Shiro AOP注解支持
         * @RequiresPermissions({"userinfo:view"})
         * @RequiresRoles({"wangjing"})等注解的支持
         * @param securityManager
         * @return
         *//*
        @Bean
        public AuthorizationAttributeSourceAdvisor getAuthorizationAttributeSourceAdvisor(@Qualifier("securityManager") DefaultWebSecurityManager securityManager) {
            AuthorizationAttributeSourceAdvisor aasa = new AuthorizationAttributeSourceAdvisor();
            aasa.setSecurityManager(securityManager);
            return aasa;
        }*/
        /**
         * 当用户无权限访问403页面而不抛异常，默认shiro会报UnauthorizedException异常
         * @return
         */
    /*    @Bean
        public SimpleMappingExceptionResolver resolver() {
            SimpleMappingExceptionResolver resolver = new SimpleMappingExceptionResolver();
            Properties properties = new Properties();
            properties.setProperty("org.apache.shiro.authz.UnauthorizedException", "/403");
            resolver.setExceptionMappings(properties);
            return resolver;
        }*/
}
