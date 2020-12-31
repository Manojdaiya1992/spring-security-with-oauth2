package com.manoj.springsecuritywithoauth;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class SpringSecurityWithOauthApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityWithOauthApplication.class, args);
	}

	
	@GetMapping("/api")
	public ResponseEntity<Object> callAPI(){
		System.out.println(SecurityContextHolder.getContext().getAuthentication().getPrincipal());
		return new ResponseEntity<>("Hi", HttpStatus.OK);
	}
	
	
	@PostMapping("/user/logout")
	public Object logout(HttpServletRequest request, HttpServletResponse response) {
		  Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		  authentication.setAuthenticated(false);
		  SecurityContextLogoutHandler securityContextLogoutHandler =  new SecurityContextLogoutHandler();
		  securityContextLogoutHandler.setClearAuthentication(true);
		  securityContextLogoutHandler.setInvalidateHttpSession(true);
		  securityContextLogoutHandler.logout(request, response, authentication);
		  return ResponseEntity.ok("User logout successfully");
	}

}
