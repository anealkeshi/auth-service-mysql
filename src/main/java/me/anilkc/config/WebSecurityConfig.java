package me.anilkc.config;

import javax.annotation.Resource;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import me.anilkc.config.handler.CustomAccessDeniedHandler;
import me.anilkc.config.handler.CustomAuthenticationEntryPoint;
import me.anilkc.config.handler.CustomLoginFailureHandler;
import me.anilkc.config.handler.CustomLoginSuccessfulHandler;
import me.anilkc.config.handler.CustomLogoutSuccessfulHandler;
import me.anilkc.service.CustomUserDetailsService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


  @Autowired
  private CustomLoginSuccessfulHandler loginSuccessfulHandler;

  @Autowired
  private CustomLoginFailureHandler loginFailureHandler;

  @Autowired
  private CustomLogoutSuccessfulHandler logoutSuccessfulHandler;

  @Autowired
  private CustomAccessDeniedHandler customAccessDeniedHandler;

  @Autowired
  private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

  @Resource(name = "customUserDetailsService")
  private CustomUserDetailsService userDetailsService;

  @Autowired
  private DataSource jdbcDatasource;

  @Override
  @Bean
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
  //@formatter:off
      auth.userDetailsService(userDetailsService)
        .and().jdbcAuthentication().dataSource(jdbcDatasource);
  // @formatter:on

  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {

  //@formatter:off
      http
      .csrf().disable()
          .formLogin()
              .loginProcessingUrl("/auth/login")
              .successHandler(loginSuccessfulHandler)
              .failureHandler(loginFailureHandler)
          .and()
              .logout()
              .deleteCookies("JSESSIONID")
              .logoutUrl("/auth/logout")
              .logoutSuccessHandler(logoutSuccessfulHandler)
          .and()
            .authorizeRequests()
            .antMatchers("/auth/login").permitAll()
            .antMatchers("/secure/admin").access("hasRole('ADMIN')")//.access("hasAuthority('ROLE_ADMIN')")
            .anyRequest().authenticated()
           .and()
             .exceptionHandling().accessDeniedHandler(customAccessDeniedHandler)
             .authenticationEntryPoint(customAuthenticationEntryPoint)
          .and()
            .anonymous()
              .disable();
  // @formatter:on
  }
  
}
