package com.ns.springsecuritywithjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ns.springsecuritywithjwt.model.User;

public interface UserRepository extends JpaRepository<User, Long> {

	User findByUsername(String username);

}
