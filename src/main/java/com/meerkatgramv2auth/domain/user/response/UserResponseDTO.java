package com.meerkatgramv2auth.domain.user.response;

import com.meerkatgramv2auth.domain.user.entity.User;
import com.meerkatgramv2auth.global.security.constant.RolePolicy;
import io.swagger.v3.oas.annotations.media.Schema;

import java.time.LocalDateTime;

@Schema(description = "유저 레스폰스")
public record UserResponseDTO(
    Long id,
    String email,
    String nick,
    RolePolicy role,
    String profile,
    LocalDateTime created_at
) {
    public static UserResponseDTO from(User user) {
        return new UserResponseDTO(
            user.getId(),
            user.getEmail(),
            user.getNick(),
            user.getRole(),
            user.getProfile(),
            user.getCreatedAt()
        );
    }
}
