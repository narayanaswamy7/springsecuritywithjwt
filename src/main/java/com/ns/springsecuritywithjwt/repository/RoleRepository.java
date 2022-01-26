package com.ns.springsecuritywithjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ns.springsecuritywithjwt.model.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {

	Role findByName(String name);

}
