package io.security.corespringsecurity.controller.login;

import io.security.corespringsecurity.domain.entity.Account;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

//    @GetMapping("/login")
//    public String login(){
//        return "user/login/login";
//    }

    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "exception", required = false) String exception,
                        Model model){

        model.addAttribute("error", error);
        model.addAttribute("exception", exception);

        return "user/login/login";
    }


    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response){
        // 1. 현재 로그인 사용자의 인증 객체를 SecurityContextHolder 에서 가져옴.
        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        // 2. SecurityContextLogoutHandler() 이용해서 로그아웃 처리.
        if(authentication != null) {
            new SecurityContextLogoutHandler().logout(
                    request, response, authentication
            );
        }

        // 3. 로그인 화면을 이동

        return "redirect:/login";
    }

    @GetMapping("denied")
    public String accessDenied(@RequestParam(value = "exception", required = false) String exception, Model model){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Account account = (Account) authentication.getPrincipal();

        model.addAttribute("username", account.getUsername());
        model.addAttribute("exception", exception);

        return "user/login/denied";
    }
}
