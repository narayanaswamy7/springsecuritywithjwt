package com.ns.springsecuritywithjwt.service;

import java.util.List;

import com.ns.springsecuritywithjwt.model.Role;
import com.ns.springsecuritywithjwt.model.User;

public interface UserService {

	User saveUser(User user);

	Role saveRole(Role role);

	void addRoleToUser(String username, String roleName);

	User getUser(String username);

	List<User> getUsers();

}
