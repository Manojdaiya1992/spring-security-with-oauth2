package com.manoj.springsecuritywithoauth.security.config.classes;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class CustomUserDetailsService implements UserDetailsService{
	
	@Override
	public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
		boolean isUserPresent = searchForUser(userName).isPresent();
		if(isUserPresent)
			return new CustomUserDetail(searchForUser(userName).get());
		return null;
	}
	
	private Optional<User> searchForUser(String userName){
		List<User> usersList = new ArrayList<>();
		usersList.add(new User("Manoj", "Dahiya", Collections.singletonList(new SimpleGrantedAuthority("User"))));
		return usersList.stream().filter(user-> user.getUsername().equalsIgnoreCase(userName)).findAny();
	}

}
