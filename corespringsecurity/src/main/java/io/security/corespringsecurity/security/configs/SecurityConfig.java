package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.provider.CustomAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.cache.spi.access.CachedDomainDataAccess;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private AuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler customAuthenticationFailureHandler;

    // 인증 및 인가
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .antMatchers("/","/users","/login*","user/login/**").permitAll()
//                .antMatchers("/mypage").hasRole("USER")
//                .antMatchers("/messages").hasRole("MANAGER")
//                .antMatchers("/config").hasRole("ADMIN")
                .antMatchers("/mypage")
                .access("hasRole('USER') or hasRole('MANAGER') or hasRole('ADMIN')")
                .antMatchers("/messages")
                .access("hasRole('MANAGER') or hasRole('ADMIN')")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()

//                .and()
//                .formLogin();
                .and()
                    .formLogin()
                    .loginPage("/login")  // LoginController 작성.
                    .loginProcessingUrl("/login_proc")  // login.html 의 form tag 의 action url 과 동일하게 설정.
                    .defaultSuccessUrl("/")
                    .successHandler(customAuthenticationSuccessHandler)
                    .failureHandler(customAuthenticationFailureHandler)
                    .permitAll() // 인증을 받지 않은 사용자도 접근할 수 있도록 설정.
                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedException());
    }

    @Bean
    public AccessDeniedHandler accessDeniedException() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }


    // Security Filter 에 대상외를 설정( 그림파일 등 )
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    // 사용자 등록
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        /**
         * AuthenticationManagerBuilder 사용하는 경우, Role 을 설정시 prfix "ROLE_" 사용하면 안됨.
         * Spring Security 에서 자동으로 prefix 를 붙여줌.
         *
         * 하지만, Table 에 Role를 저장하는 경우는 prefix 를 붙여서 저장해야 함.
         */
//        String password = passwordEncoder().encode("1111");
//
//        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
//        auth.inMemoryAuthentication().withUser("manager").password(password).roles("USER","MANAGER");
//        auth.inMemoryAuthentication().withUser("admin").password(password).roles("USER", "MANAGER", "ADMIN");

        //auth.userDetailsService(userDetailsService);

//         CustomAuthenticationProvider 를 구현 후 사용 대체해야 함.
        auth.authenticationProvider(authenticationProvider());
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    // 사용자 등록시 패스워드 암호화 기능
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
