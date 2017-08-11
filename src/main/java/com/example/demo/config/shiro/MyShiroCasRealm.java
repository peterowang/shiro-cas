package com.example.demo.config.shiro;

import com.example.demo.model.UserInfo;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cas.CasRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;

/**
 * Created by BFD-593 on 2017/8/11.
 */
public class MyShiroCasRealm extends CasRealm {
    private static final Logger logger = LoggerFactory.getLogger(MyShiroCasRealm.class);
        @PostConstruct
        public void initProperty(){
            // cas地址
            setCasServerUrlPrefix(ShiroConfiguration.casServerUrlPrefix);
            // 客户端回调地址
            setCasService(ShiroConfiguration.shiroServerUrlPrefix + ShiroConfiguration.casFilterUrlPattern);
        }

//    /**
//     * 1、CAS认证 ,验证用户身份
//     * 2、将用户基本信息设置到会话中(不用了，随时可以获取的)
//     */
//    @Override
//    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
//
//        AuthenticationInfo authc = super.doGetAuthenticationInfo(token);
//
//        String account = (String) authc.getPrincipals().getPrimaryPrincipal();
//
//        User user = userDao.getByName(account);
//        //将用户信息存入session中
//        SecurityUtils.getSubject().getSession().setAttribute("user", user);
//
//        return authc;
//    }

    /**
     * 此方法调用 hasRole,hasPermission的时候才会进行回调.
     *
     * 权限信息.(授权): 1、如果用户正常退出，缓存自动清空； 2、如果用户非正常退出，缓存自动清空；
     * 3、如果我们修改了用户的权限，而用户不退出系统，修改的权限无法立即生效。 （需要手动编程进行实现；放在service进行调用）
     * 在权限修改后调用realm中的方法，realm已经由spring管理，所以从spring中获取realm实例， 调用clearCached方法；
     * :Authorization 是授权访问控制，用于对用户进行的操作授权，证明该用户是否允许进行当前操作，如访问某个链接，某个资源文件等。
     *
     * @param principals
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        logger.info("开始权限配置");
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
//        UserInfo userInfo = (UserInfo)principals.getPrimaryPrincipal();
        //这里应该查询数据库，拿到用户的所有角色，遍历添加角色到权限对象中，再通过角色获取权限，添加到权限对象中
       /* for (Role role: userInfo.getRoleList()) {
            authorizationInfo.addRole(role.getRole());
            for (SysPermission p: role.getPermissions()) {
                authorizationInfo.addStringPermission(p.getPermission());
            }
        }*/
        //为了节省时间，这边我先给它写死，做测试
        authorizationInfo.addRole("wangjing");
        authorizationInfo.addStringPermission("userinfo:view");
        return authorizationInfo;
    }
}
