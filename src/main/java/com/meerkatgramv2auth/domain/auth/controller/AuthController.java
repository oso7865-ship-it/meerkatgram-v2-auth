package com.meerkatgramv2auth.domain.auth.controller;

import com.meerkatgramv2auth.domain.auth.request.LoginRequestDTO;
import com.meerkatgramv2auth.global.response.GlobalResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@Tag(name = "인증 API", description = "인증 담당")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/login")
    public ResponseEntity<GlobalResponse<Void>> login(
        @Valid @RequestBody LoginRequestDTO loginRequestDTO,
        HttpServletResponse httpServletResponse
    ) {
        return GlobalResponse.success();
    }
}
