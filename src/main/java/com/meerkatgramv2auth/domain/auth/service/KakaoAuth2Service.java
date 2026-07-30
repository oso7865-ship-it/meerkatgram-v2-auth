package com.meerkatgramv2auth.domain.auth.service;

import com.meerkatgramv2auth.domain.auth.repository.AuthRepository;
import com.meerkatgramv2auth.domain.user.entity.User;
import com.meerkatgramv2auth.global.config.jpa.JPAWithDeleted;
import com.meerkatgramv2auth.global.response.constant.CustomResponseCode;
import com.meerkatgramv2auth.global.security.constant.ProviderPolicy;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class KakaoAuth2Service implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final AuthRepository authRepository;
    private final PasswordEncoder passwordEncoder;

    @JPAWithDeleted
    @Override
    public OAuth2User loadUser(@NonNull OAuth2UserRequest request) throws OAuth2AuthenticationException {
        // Spring Security 기본 구현체로 카카오에서 유저 정보를 흭득
        OAuth2User oAuthUser = new DefaultOAuth2UserService().loadUser(request);

        // 응답에 필요한 값을 파싱
        Map<String, Object> attributes = oAuthUser.getAttributes();
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

        String email = (String) kakaoAccount.get("email");
        String nickName = (String) profile.get("nickname");
        String profileImageUrl = (String) profile.get("profile_image_url");

        // 이메일로 유저 조회
        // 1. 미가입자
        // 2. 다른 방식으로 회원가입이 되어 있는 자
        // 3. 탈퇴한 회원(Soft Delete)
        //    3-1. 같은 방식으로 회원가입 했던 자
        //    3-2. 다른 방식으로 회원가입 했던 자

        User user = authRepository.findByEmail(email)
                        .orElseGet(() -> this.createKakaoUser(email,nickName,profileImageUrl));
        // Provider가 카카오가 아닐경우
        if (!user.getProvider().equals(ProviderPolicy.KAKAO)) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                    CustomResponseCode.ALREADY_REGISTERED_ERROR.getCode(),
                    CustomResponseCode.ALREADY_REGISTERED_ERROR.name(),
                    null
                )
            );
        }
        // 탈퇴한 유저일 경우 복구 처리
        if (user.getDeletedAt() != null) {
            user.setDeletedAt(null);
            authRepository.save(user);
        }

        return new DefaultOAuth2User(
            List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole())),
            Map.of(
                "id", user.getId(),
                "email", user.getEmail(),
                "role", user.getRole()
            ),
            "id"
        );
    }

    private User createKakaoUser(String email, String nickname, String profile){
        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
        user.setNick(nickname);
        user.setProfile(profile != null ? profile : "");
        return authRepository.save(user);
    }
}
