package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.security.service.AccountContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 인증 및 인가 처리를 구현.
     * 인증 : 사용자명으로 조회 -> PW 비교 -> 최종 인가 성공 토큰
     * @param authentication the authentication request object.
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        // authenticate 메소드의 Authentication 은 크게 두 가지 있음.
        // 메소드의 매개변수는 로그인 화면에서 입력한 데이터
        // 마지막에 반환하는 Authentication 객체는 인증이 성공된 Authentication 임.

        // 1. 현재 로그인하려고 하는 사용자의 정보를 취득.
        String username = authentication.getName();
        String password = (String)authentication.getCredentials();

        // 2. 사용자 정보를 DB에서 조회
        AccountContext accountContext =
                (AccountContext)userDetailsService.loadUserByUsername(username);

        // 3. 화면의 PW와 DB의 PW 를 비교 ( Exception 처리 )
        if(!passwordEncoder.matches(password, accountContext.getAccount().getPassword())){
            throw new BadCredentialsException("BadCredentialsException");
        }

        // 4. 최종 인증 토큰 생성 및 반환
        /**
         * 여기까지 진행이 되면 인증이 정상적으로 모두 완료가 되는 상태임.
         * 따라서, 인증에 성공한 인증 토큰을 만들어서 반환해야 함.
         *
         * 그리고, UsernamePasswordAuthenticationToken 에느 두 가지의 생성자가 있음.
         *
         * 1. UsernamePasswordAuthenticationToken(Object principal, Object credentials)
         *    처음 로그인해서 인증을 시도하려고 할 때 사용되는 생성자.
         *
         * 2. UsernamePasswordAuthenticationToken(Object principal, Object credentials,
         * 			Collection<? extends GrantedAuthority> authorities)
         * 	  최종적으로 인증에 성공한 경우에 사용되는 생성자.
         *
         */

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(
                        accountContext.getAccount(), null,
                        accountContext.getAuthorities()
                );

        return authenticationToken;
    }

    /**
     * UsernamePasswordAuthenticationToken 이 현재 매개변수로 전달된 이 클래스의 타입과
     * 일치할 때 CustomAuthenticationProvider 클래스가 인증을 처리하도록 하는 조건.
     *
     * @param authentication
     * @return
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
