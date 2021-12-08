package com.tasks.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true, order=1)
@EnableTransactionManagement(order=0)
//@Order(Ordered.HIGHEST_PRECEDENCE)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;
        
    @Autowired
    private JwtTokenProvider tokenProvider;
    
    @Override
    public void configure(WebSecurity web) throws Exception {
    	web.ignoring()
    		.antMatchers("/webjars/**")
    		.antMatchers("/css/**")
    		.antMatchers("/javascript-libs/**")
    		.antMatchers("/application/**")
    		.antMatchers("/react-libs/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
    	    .addFilter( new JwtAuthorizationFilter(this.tokenProvider, customAuthenticationManager()))
        	.authorizeRequests()
        	.antMatchers(HttpMethod.GET,  "/api/projects").permitAll() 
        	.antMatchers(HttpMethod.POST,  "/api/projects").hasRole("ADMIN")
        	.antMatchers(HttpMethod.GET,  "/api/projects/{id}").permitAll() //si no estas autenticado no puedes -  no hay front option
        	.antMatchers(HttpMethod.PUT,  "/api/projects/{id}").hasRole("ADMIN")
        	.antMatchers(HttpMethod.DELETE,  "/api/projects/{id}").hasRole("ADMIN")
        	.antMatchers(HttpMethod.GET,  "/api/projects/{id}/tasks").permitAll()
        
        
        	.antMatchers(HttpMethod.POST,  "/api/login").permitAll() 
        	.antMatchers(HttpMethod.GET,  "/api/users").hasRole("ADMIN")
        
        
        	.antMatchers(HttpMethod.GET,  "/api/tasks").permitAll() 
        	.antMatchers(HttpMethod.GET,  "/api/tasks/{id}").permitAll() 
        	.antMatchers(HttpMethod.POST,  "/api/tasks/").hasRole("ADMIN")
        	.antMatchers(HttpMethod.PUT,  "/api/tasks/{id}").hasRole("ADMIN") 
        	.antMatchers(HttpMethod.DELETE,  "/api/tasks/{id}").hasRole("ADMIN") 
        	
        	.antMatchers(HttpMethod.POST,  "/api/tasks/{id}/changeState").hasRole("ADMIN")
        	.antMatchers(HttpMethod.POST,  "/api/tasks/{id}/changeResolution").hasRole("USER")
        	.antMatchers(HttpMethod.POST,  "/api/tasks/{id}/changeProgress").hasRole("USER")
        	
        	.antMatchers(HttpMethod.POST,  "/api/comments/").hasAnyRole("ADMIN", "USER") //isAuthenticated - memoria
        	.antMatchers(HttpMethod.GET,  "/api/comments/{id}").permitAll() //si no estas logueado que
        
            .antMatchers(HttpMethod.GET,  "/swagger-ui.html").permitAll()
            .antMatchers(HttpMethod.GET,  "/swagger-resources/**").permitAll()
            .antMatchers(HttpMethod.GET,  "/v2/api-docs").permitAll()
            
            .antMatchers(HttpMethod.GET,  "/dashboard/**").permitAll()
            .anyRequest().denyAll(); 
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }
    
    @Bean
    public AuthenticationManager customAuthenticationManager() throws Exception {
        return authenticationManager();
    }

}
