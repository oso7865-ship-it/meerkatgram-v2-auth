package com.meerkatgramv2auth.domain.auth.service;

import com.meerkatgramv2auth.domain.auth.repository.AuthRepository;
import com.meerkatgramv2auth.domain.auth.request.LoginRequestDTO;
import com.meerkatgramv2auth.domain.auth.request.RegistrationRequestDTO;
import com.meerkatgramv2auth.domain.auth.response.AuthResponseDTO;
import com.meerkatgramv2auth.domain.user.entity.User;
import com.meerkatgramv2auth.global.config.jpa.JPAWithDeleted;
import com.meerkatgramv2auth.global.cookie.CookieManager;
import com.meerkatgramv2auth.global.error.custom.business.DuplicatedResourceException;
import com.meerkatgramv2auth.global.error.custom.business.InvalidTokenException;
import com.meerkatgramv2auth.global.error.custom.business.NotRegisteredException;
import com.meerkatgramv2auth.global.jwt.JwtProvider;
import com.meerkatgramv2auth.global.security.constant.ProviderPolicy;
import com.meerkatgramv2auth.global.security.constant.RolePolicy;
import jakarta.servlet.http.HttpServletRequest;
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

    @Transactional(rollbackFor = Exception.class)
    public AuthResponseDTO reissue(HttpServletRequest request, HttpServletResponse response) {
        // 쿠키 리프레쉬 토큰 흭득
        String refreshToken = cookieManager.getRefreshTokenToCookie(request)
             .orElseThrow(() -> new InvalidTokenException("리프레시 토큰 없음"));
        long userId = Long.parseLong(jwtProvider.extractClaims(refreshToken).getSubject());
        // 유저 획득 및 가입 여부 확인
        User user = authRepository.findById(userId)
                        .orElseThrow(() -> new InvalidTokenException("유효하지 않는 회원입니다."));
        // 비로그인 상태 확인
        if (user.getRefreshToken() == null) {
            throw new InvalidTokenException("로그인해주세요");
        }

        // 리프래시 토큰 일치 확인
        if (!user.getRefreshToken().equals(refreshToken)) {
            throw new InvalidTokenException("토큰 올바르지 않습니다.");
        }

        // 인증 정보생성 및 리턴
        return this.generateAuthentication(response,user);
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

    @Transactional(rollbackFor = Exception.class)
    public void logout (HttpServletResponse response, long userId){

        User user = authRepository.findById(userId)
                        .orElseThrow(() -> new InvalidTokenException("유효하지 않는 회원입니다."));

        user.setRefreshToken(null);
        authRepository.save(user);

        cookieManager.removeRefreshTokenToCookie(response);

    }

    @JPAWithDeleted
    @Transactional(rollbackFor = Exception.class)
    public void registration(RegistrationRequestDTO request) {

        if (authRepository.existsByEmail(request.email())) {
            throw new DuplicatedResourceException("이미 가입된 회원입니다.");
        }

        User newUser = new User();
        newUser.setEmail(request.email());
        newUser.setPassword(passwordEncoder.encode(request.password()));
        newUser.setNick(request.nick());
        newUser.setProfile(request.profile());
        newUser.setProvider(ProviderPolicy.NONE);
        newUser.setRole(RolePolicy.NORMAL);
        authRepository.save(newUser);

    }




}
