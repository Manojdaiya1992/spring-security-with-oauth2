package com.manoj.springsecuritywithoauth;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.web.filter.GenericFilterBean;

import com.manoj.springsecuritywithoauth.security.config.classes.CustomUserDetailsService;

@Configuration
@EnableWebSecurity
@EnableResourceServer
public class OauthSecurityWebConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private CustomUserDetailsService userDetailsService;
	
	@Bean
	@Override
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		 auth.userDetailsService(userDetailsService).passwordEncoder(new PasswordEncoder() {
			
			@Override
			public boolean matches(CharSequence arg0, String arg1) {
				return arg0.toString().equals(arg1); 
			}
			
			@Override
			public String encode(CharSequence arg0) {
				return arg0.toString();
			}
		});
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().authorizeRequests().antMatchers(HttpMethod.OPTIONS, "/**").permitAll();
		http.exceptionHandling()
		.authenticationEntryPoint(
				(request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
		.and().authorizeRequests()
		.antMatchers("/login")
		.permitAll().anyRequest().authenticated().and().logout(l -> l
	            .logoutUrl("/user/logout").logoutSuccessUrl("/").permitAll()
		        ).sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		//.and().addFilterBefore(customFilter(), FilterSecurityInterceptor.class)
		;
	}
	
	@Bean
	public Filter customFilter() {
		return new GenericFilterBean() {
			
			@Override
			public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
					throws IOException, ServletException {
				// TODO Auto-generated method stub
				HttpServletRequest servletRequest =  (HttpServletRequest) request;
				String authorization = servletRequest.getHeader(HttpHeaders.AUTHORIZATION);
				System.out.println("Authorization " + authorization);
				System.out.println("hhhhhhhhhhhhhhhhhhhhhhh");
			/*	 if(authorization.startsWith("Bearer")) {
				      
				 }*/
				chain.doFilter(request, response);
			}
		};
	}
	
	

}
