package com.github.lisama569.cryptokeylifecyclejava.web.dto;

/** 接口出入参 DTO 汇总。 */
public final class Dtos {
    private Dtos() { }

    public record EncryptRequest(String plaintext) { }
    public record EncryptResponse(String ciphertext, int keyVersion) { }
    public record DecryptRequest(String ciphertext) { }
    public record DecryptResponse(String plaintext, int keyVersion) { }
    public record RotateResponse(int previousVersion, int activeVersion) { }
    public record RevokeRequest(Integer version) { }
    public record DecommissionRequest(Integer version) { }
    public record VersionView(int version, String state, String createdAt, String retiredAt,
                              String revokedAt, String decommissionedAt) { }
    public record ErrorResponse(String error, String message) { }
}
