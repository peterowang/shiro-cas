package com.example.demo.dao;

import com.example.demo.model.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Created by BFD-593 on 2017/8/8.
 */
public interface UserInfoRepository extends JpaRepository<UserInfo,Long> {
    public UserInfo findByUsername(String username);

    public UserInfo save(UserInfo userInfo);
}
