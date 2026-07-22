package com.meerkatgramv2auth.domain.auth.controller;

import com.meerkatgramv2auth.domain.auth.request.LoginRequestDTO;
import com.meerkatgramv2auth.domain.auth.response.AuthResponseDTO;
import com.meerkatgramv2auth.domain.auth.service.AuthService;
import com.meerkatgramv2auth.global.response.GlobalResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "인증 API", description = "인증 담당")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    // @PreAuthorize("isAuthenticated()") 인증된 사람만 접근하게 만드는 방법
    // @PreAuthorize("hasAllRoles('NORMAL', 'SUPER')") 특정 권한을 가진 사람만 접근하게 만드는 방법
    @PostMapping("/login")
    public ResponseEntity<GlobalResponse<AuthResponseDTO>> login(
        @Valid @RequestBody LoginRequestDTO loginRequestDTO,
        HttpServletResponse httpServletResponse
    ) {

        return GlobalResponse.success(authService.login(httpServletResponse,loginRequestDTO));
    }
}
