package com.example.demo.web;

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Created by BFD-593 on 2017/8/9.
 */
@Controller
@RequestMapping("/userinfo")
public class UserController {
    /**
     * 要查看必须有角色wangjing和有权限userinfo:view
     * @return
     */
    @RequestMapping("/userList")
    @RequiresPermissions({"userinfo:view"})
    @RequiresRoles({"wangjing"})
    public String userInfo(){
        return "userInfo";
    }

    /**
     * 用户添加必须有查看和删除权限;
     * @return
     */
    @RequestMapping("/userAdd")
    @RequiresPermissions({"userinfo:view","userinfo:add"})
    public String userInfoAdd(){
        return "userAdd";
    }

    /**
     * 要删除必须有查看和删除权限
     * @return
     */
    @RequiresPermissions({"userinfo:view","userinfo:del"})
    @RequestMapping("/userDel")
    public String userInfoDel() {
        return "userDel";
    }

}
