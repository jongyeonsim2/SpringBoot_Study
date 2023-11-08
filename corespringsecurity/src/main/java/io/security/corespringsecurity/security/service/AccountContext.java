package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.entity.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

/**
 * CustomerUserDetailsService.loadUserByUsername 의 반환형으로 사용하는 클래스
 * spring secutiry 의 User 클래스를 상속받았으므로, UserDetails 타입이 됨.
 */
public class AccountContext extends User {

    private final Account account;

    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities);
        this.account = account;
    }

    public Account getAccount() {return account;}
}
