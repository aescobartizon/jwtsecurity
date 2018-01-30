package com.aescobartizon.jwt.jwtsecurity.user;

import org.springframework.data.jpa.repository.JpaRepository;

public interface  ApplicationUserRepository extends JpaRepository<ApplicationUser, Long>  {
	ApplicationUser findByUsername(String username);
}
