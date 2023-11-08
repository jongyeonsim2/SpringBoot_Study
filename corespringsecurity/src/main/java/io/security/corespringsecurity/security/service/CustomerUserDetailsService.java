package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service("userDetailsService") // SecurityConfig 에서 사용할 수 있도록  bean 으로 설정하는 것임.
public class CustomerUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    /**
     * 오버라이드 하는 메소드의 반환형이 UserDetails. => interface 임.
     * interface 를 구현한 클래스가 User 클래스를 Spring Security 에서 제공됨.
     * 따라서, User 상속받아서 AccountText 클래스를 만들어서 사용.
     *
     * AccountText 를 사용하게 되면, 오버라이드 되는 메소드의 반환형과 일치됨.
     *
     * @param username the username identifying the user whose data is required.
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //1. 데이터베이스에서 등록된 사용자 조회
        Account account = userRepository.findByUsername(username);

        //2. 등록된 사용자가 아니면, Exception throws.
        if(account == null) {
            throw new UsernameNotFoundException("UsernameNotFoundException");
        }

        //3. 권한 객체를 생성.
        // SimpleGrantedAuthority 는 GrantedAuthority 의 구현체임.
        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(account.getRole()));

        //4. AccountContex 객체로 생성해서 반환.
        AccountContext accountContext = new AccountContext(account, roles);

        return accountContext;
    }
}
