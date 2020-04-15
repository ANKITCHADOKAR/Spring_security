package com.ankit.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/*
	Http Basic Authentication using spring boot security
*/

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	// overriding AuthenticationManagerBuilder for custom security
	// in memory authentication example
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		auth
			.inMemoryAuthentication()
			.withUser("user1").password(getPasswordEncoder().encode("user1"))
			.roles("ADMIN").authorities("AUTH_Test1", "AUTH_Test2")
			.and()
			.withUser("user2").password(getPasswordEncoder().encode("user2")).roles("USER")
			.and()
			.withUser("user3").password(getPasswordEncoder().encode("user3"))
			.roles("MANAGER").authorities("AUTH_Test1");
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		// role based authorization
		http
			.authorizeRequests()
			.antMatchers("/index.html").permitAll()
			.antMatchers("/profile/index").authenticated()
			.antMatchers("/admin/index").hasRole("ADMIN")
			.antMatchers("/management/index").hasAnyRole("ADMIN","MANAGER")
			.antMatchers("/api/public/test1").hasAuthority("AUTH_Test1") // configure permission based authorities
			.antMatchers("/api/public/test2").hasAuthority("AUTH_Test2")
			.and()
			.httpBasic();
		
		
		
		// common authorization
//		http
//			.authorizeRequests()
//			.anyRequest().authenticated()
//			.and()
//			.httpBasic();
//		
	}
	
	@Bean
	PasswordEncoder getPasswordEncoder() {
		return new BCryptPasswordEncoder(); 
		
	}
	
}
