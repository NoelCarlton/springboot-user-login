package com.noel.handbook.accesscontroll.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserModel {

	private String name;
	private String pwd;
	private Integer type;
}
