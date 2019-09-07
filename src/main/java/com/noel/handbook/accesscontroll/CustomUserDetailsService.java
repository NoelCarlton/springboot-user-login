/**
* <p>Title: UserDetailsService.java</p>
* <p>Description: 系统用户信息校验，权限检查</p>
* <p>Copyright: Copyright (c) 2019</p>
* <p>Company: cbpm</p>
* @author noel
* @date 2019年9月6日
 */
package com.noel.handbook.accesscontroll;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.noel.handbook.accesscontroll.dao.IUser;
import com.noel.handbook.accesscontroll.model.UserModel;

/**
 * 用户权限检查
 * @author noel
 * @date 2019年9月6日
 */
@Service
public class CustomUserDetailsService implements UserDetailsService{
	
	private static final Logger log = LoggerFactory.getLogger(CustomUserDetailsService.class);

	@Resource
	private IUser iUser;
	
	/* (non-Javadoc)
	 * @see org.springframework.security.core.userdetails.UserDetailsService#loadUserByUsername(java.lang.String)
	 */
	@Override
	public UserDetails loadUserByUsername(String arg0) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		UserModel userModel = iUser.getUser(arg0);
		log.info("验证机制里面的用户",userModel);
		if(null == userModel) {
			throw new UsernameNotFoundException("用户不存在");
		}
		List<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
		if(userModel.getType()==0) {
			authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
		}else {
			//其它所有用户都认为是普通用户
			authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
		}
		return new User(userModel.getName(), userModel.getPwd(), authorities);
	}

}
