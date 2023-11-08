package io.security.corespringsecurity.security.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        // 에러 메세지
        String errorMessage = "Invalid Username or Password";

        // 예외(BadCredentialsException)를 확인
        if(exception instanceof BadCredentialsException){
            errorMessage = "Invalid Username or Password";
        }

        // 인증 실패 요청 페이지로 로그인 화면으로 설정. 에러에 대한 정보를 전달.
        // LoginController 에서 처리되도록 구현.
        setDefaultFailureUrl("/login?error=true&exception=" + errorMessage);

        // 설정이 완료된 후 나머지 처리는 부모에게 위임.
        super.onAuthenticationFailure(request, response, exception);
    }
}
