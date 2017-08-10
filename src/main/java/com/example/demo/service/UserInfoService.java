package com.example.demo.service;

import com.example.demo.dao.UserInfoRepository;
import com.example.demo.model.UserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Created by BFD-593 on 2017/8/8.
 */
@Service
public class UserInfoService {
    @Autowired
    private UserInfoRepository userInfoRepository;

    public UserInfo findByUsername(String username){
        return userInfoRepository.findByUsername(username);
    }
}
