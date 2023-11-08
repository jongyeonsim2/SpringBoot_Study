package io.security.corespringsecurity.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    // 사용자 요청 경로등을 저장하고 있는 객체.
    private RequestCache requestCache = new HttpSessionRequestCache();

    // 요청 경로로 이동시 위임해서 처리할 수 있는 객체.
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        // 1. 기본 이동 경로를 설정. root 경로로 지정.
        setDefaultTargetUrl("/");

        // 2. RequestCache 객체를 취득.
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        // 3. RequestCache 객체의 null 체크 및 사용자 요청 경로 정보에 대한 이동을 분기처리.
        if(savedRequest != null){
            // 사용자가 이전에 가려고 했던 요청 경로를 취득 후 이동.
            String targetUrl = savedRequest.getRedirectUrl();
            // 이동을 위임.
            redirectStrategy.sendRedirect(request, response, targetUrl);
        }else{
            // 기본 경로로 이동.
            redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
        }
    }
}
