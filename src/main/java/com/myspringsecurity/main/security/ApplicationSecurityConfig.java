package com.myspringsecurity.main.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

//If you want all the course git clone git@github.com:amigoscode/spring-boot-security-course.git

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig  extends WebSecurityConfigurerAdapter {

    @Autowired
    private final PasswordEncoder passwordEncoder;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .authorizeRequests()
                .antMatchers("/","index","/css/*","/js/*")
                .permitAll()
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAnyAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAnyAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAnyAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(),ApplicationUserRole.ADMINTRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("student")
                .password(passwordEncoder.encode("student"))
//                .roles(ApplicationUserRole.STUDENT.name()) // ROLE_STUDENT
                .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
                .build();

       UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin"))
//               .roles(ApplicationUserRole.ADMIN.name()) // ROLE_STUDENT
               .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
                .build();


        UserDetails admintrain = User.builder()
                .username("admintrainee")
                .password(passwordEncoder.encode("admintrainee"))
//                .roles(ApplicationUserRole.ADMINTRAINEE.name()) // ROLE_STUDENT
                .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
                .build();


        return new InMemoryUserDetailsManager(user,admin,admintrain);
    }
}
