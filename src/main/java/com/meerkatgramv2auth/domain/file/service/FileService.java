package com.meerkatgramv2auth.domain.file.service;

import com.meerkatgramv2auth.domain.file.response.FileResponseDTO;
import com.meerkatgramv2auth.global.minio.MinioManager;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
@RequiredArgsConstructor
public class FileService {
    private final MinioManager minioManager;

    public FileResponseDTO uploadProfile(MultipartFile file) {
        // 파일 경로 생성
        String objectKey = minioManager.generateObjectKey(file);
        // 파일 저장
        minioManager.uploadFile(objectKey, file);
        // 값 반환
        return FileResponseDTO.from(minioManager.createMinioObjectUri(objectKey));


    }
}
