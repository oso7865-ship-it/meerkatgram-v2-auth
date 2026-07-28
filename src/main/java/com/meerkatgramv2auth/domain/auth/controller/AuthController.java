package com.meerkatgramv2auth.domain.auth.controller;

import com.meerkatgramv2auth.domain.auth.request.LoginRequestDTO;
import com.meerkatgramv2auth.domain.auth.request.RegistrationRequestDTO;
import com.meerkatgramv2auth.domain.auth.response.AuthResponseDTO;
import com.meerkatgramv2auth.domain.auth.service.AuthService;
import com.meerkatgramv2auth.global.config.openapi.CustomApiResponse;
import com.meerkatgramv2auth.global.response.GlobalResponse;
import com.meerkatgramv2auth.global.response.constant.CustomResponseCode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
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
    @Operation(summary = "로그인 처리", description = "이메일과 비밀번호를 입력하세요")
    @SecurityRequirements
    @CustomApiResponse(value = {
        CustomResponseCode.NOT_REGISTERED_ERROR,
        CustomResponseCode.INVALID_PARAMETER_ERROR,
        CustomResponseCode.DB_ERROR,
        CustomResponseCode.SYSTEM_ERROR
    })
    @PostMapping("/login")
    public ResponseEntity<GlobalResponse<AuthResponseDTO>> login(
        @Valid @RequestBody LoginRequestDTO loginRequestDTO,
        HttpServletResponse httpServletResponse
    ) {

        return GlobalResponse.success(authService.login(httpServletResponse,loginRequestDTO));
    }

    @Operation(summary = "로그아웃 처리", description = "로그아웃")
    @PreAuthorize("isAuthenticated()")
    @CustomApiResponse(value = {
        CustomResponseCode.UNAUTHENTICATED_ERROR,
        CustomResponseCode.INVALID_TOKEN_ERROR,
        CustomResponseCode.DB_ERROR,
        CustomResponseCode.SYSTEM_ERROR
    })
    @PostMapping("/logout")
    public ResponseEntity<GlobalResponse<Void>> logout(
        Authentication authentication,
        HttpServletResponse response
    ) {
        long userId = Long.parseLong(authentication.getName());
        authService.logout(response,userId);
        return GlobalResponse.success();
    }

    @Operation(summary = "토큰재발급 처리", description = "토큰 재발급")
    @PreAuthorize("isAuthenticated()")
    @CustomApiResponse(value = {
        CustomResponseCode.INVALID_TOKEN_ERROR,
        CustomResponseCode.DB_ERROR,
        CustomResponseCode.SYSTEM_ERROR
    })
    @PostMapping("/reissue-token")
    public ResponseEntity<GlobalResponse<AuthResponseDTO>> reissue(
        HttpServletResponse response, HttpServletRequest request
    ) {
        return GlobalResponse.success(authService.reissue(request,response));
    }

    @Operation(summary = "회원가입 처리")
    @CustomApiResponse(value = {
            CustomResponseCode.DUPLICATED_DATA_ERROR,
            CustomResponseCode.INVALID_PARAMETER_ERROR,
            CustomResponseCode.DB_ERROR,
            CustomResponseCode.SYSTEM_ERROR
    })
    @PostMapping("/registration")
    public ResponseEntity<GlobalResponse<Void>> registration(
            @Valid @RequestBody RegistrationRequestDTO requestDTO
            ) {
        authService.registration(requestDTO);
        return GlobalResponse.success();
    }
}
