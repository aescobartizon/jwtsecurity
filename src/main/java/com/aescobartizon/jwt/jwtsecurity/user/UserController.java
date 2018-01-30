package com.aescobartizon.jwt.jwtsecurity.user;

import static com.aescobartizon.jwt.jwtsecurity.security.SecurityUtils.HEADER_STRING;
import static com.aescobartizon.jwt.jwtsecurity.security.SecurityUtils.TOKEN_PREFIX;

import javax.servlet.http.HttpServletResponse;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.aescobartizon.jwt.jwtsecurity.security.SecurityUtils;

@RestController
@RequestMapping("/users")
public class UserController {

	private ApplicationUserRepository applicationUserRepository;
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	public UserController(ApplicationUserRepository applicationUserRepository,
						  BCryptPasswordEncoder bCryptPasswordEncoder) {
		this.applicationUserRepository = applicationUserRepository;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
	}

	@PostMapping("/sign-up")
	public void signUp(@RequestBody ApplicationUser user, HttpServletResponse res) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		applicationUserRepository.save(user);
		res.addHeader(HEADER_STRING, TOKEN_PREFIX + " " + SecurityUtils.generateToken(user.getUsername()));
	}
}
