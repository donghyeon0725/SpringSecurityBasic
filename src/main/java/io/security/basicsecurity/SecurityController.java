package io.security.basicsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.Mapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class SecurityController {
    @GetMapping("/")
    public String index(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Authentication authFromSession =
                ((SecurityContext) request
                                        .getSession()
                                        .getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)
                ).getAuthentication();
        return "home";
    }

    @GetMapping("/thread")
    public String thread() {
        new Thread(() -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            // default 인 경우 main에만 저장을 할 수 있는 모드이기 때문에 자식 스레드에서는 SecurityContextHolder.getContext().getAuthentication();에서 참조할 수 없다.
        }).start();

        return "thread";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/user")
    public String user() {
        return "user 권한이 필요한 페이지";
    }

    @GetMapping("/admin/pay")
    public String adminOnly() {
        return "admin 권한이 필요한 페이지";
    }

    @GetMapping("/admin/configure")
    public String adminAndSys() {
        return "admin 또는 sys 권한이 필요한 페이지";
    }

    @GetMapping("/denied")
    public String denied() {
        return "이 자원에 대한 권한이 없습니다";
    }

}
