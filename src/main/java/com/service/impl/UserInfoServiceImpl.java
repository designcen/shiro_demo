package com.service.impl;

import com.dao.UserInfoDao;
import com.entity.UserInfo;
import org.springframework.stereotype.Service;
import com.service.UserInfoService;

import javax.annotation.Resource;

@Service
public class UserInfoServiceImpl implements UserInfoService {

    @Resource
    UserInfoDao userInfoDao;

    @Override
    public UserInfo findByUsername(String username) {
        return userInfoDao.findByUsername(username);
    }
}