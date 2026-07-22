package com.meerkatgramv2auth.domain.auth.service;

import com.meerkatgramv2auth.domain.auth.repository.AuthRepository;
import com.meerkatgramv2auth.domain.auth.request.LoginRequestDTO;
import com.meerkatgramv2auth.domain.auth.response.AuthResponseDTO;
import com.meerkatgramv2auth.domain.user.entity.User;
import com.meerkatgramv2auth.global.cookie.CookieManager;
import com.meerkatgramv2auth.global.error.custom.NotRegisteredException;
import com.meerkatgramv2auth.global.jwt.JwtProvider;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthRepository authRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final CookieManager cookieManager;

    @Transactional(rollbackFor = Exception.class)
    public AuthResponseDTO login(HttpServletResponse httpServletResponse, LoginRequestDTO loginRequestDTO) {
        // 유저 정보 조회
        User user = authRepository.findByEmail(loginRequestDTO.email())
            .orElseThrow(() -> new NotRegisteredException("아이디 또는 비밀번호가 일치하지 않습니다."));
        // 비밀번호 체크
        if (!passwordEncoder.matches(loginRequestDTO.password(), user.getPassword())) {
            throw new NotRegisteredException("아이디 또는 비밀번호가 일치하지 않습니다.");
        }
        return this.generateAuthentication(httpServletResponse, user);
    }

    private AuthResponseDTO generateAuthentication(HttpServletResponse response, User user) {
        String accessToken = jwtProvider.generateAccessToken(user);
        String refreshToken = jwtProvider.generateRefreshToken(user);

        // 리프래시토큰 DB 저장 처리
        user.setRefreshToken(refreshToken);
        authRepository.save(user);

        // 리프래시토큰 쿠키 저장
        cookieManager.setRefreshTokenToCookie(response, refreshToken);
        return AuthResponseDTO.from(user,accessToken);
    }
}
