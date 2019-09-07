package com.noel.handbook.accesscontroll.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class MvcConfig implements WebMvcConfigurer {

	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
		// TODO Auto-generated method stub
		registry.addViewController("/home").setViewName("/home");
		registry.addViewController("/").setViewName("/home");
		registry.addViewController("/login").setViewName("/login");
		registry.addViewController("/hello").setViewName("/hello");
	}

	
}
