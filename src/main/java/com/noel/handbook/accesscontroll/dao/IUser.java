package com.noel.handbook.accesscontroll.dao;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.noel.handbook.accesscontroll.model.UserModel;

@Mapper
public interface IUser {

	/**
	 * 根据用户名获取一个用户
	 * @return 用户信息
	 * @author noel
	 * @date 2019年9月7日
	 */
	UserModel getUser(@Param("name")String name);
}
