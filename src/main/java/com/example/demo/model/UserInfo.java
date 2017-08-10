package com.example.demo.model;

import javax.persistence.*;
import java.io.Serializable;

/**
 * Created by archerlj on 2017/6/30.
 */

@Entity
@Table(name="user_info")
public class UserInfo implements Serializable {

    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;//用户id;

    @Column(unique = true, name = "username")
    private String username;//账号.
    @Column(name = "password")
    private String password; //密码;
    @Column(name = "salt")
    private String salt;//加密密码的盐
    @Column(name = "state")
    private byte state;//用户状态,0:创建未认证（比如没有激活，没有输入验证码等等）--等待验证的用户 , 1:正常状态,2：用户被锁定.


    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public byte getState() {
        return state;
    }

    public void setState(byte state) {
        this.state = state;
    }


}
