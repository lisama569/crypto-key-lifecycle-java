package com.github.lisama569.cryptokeylifecyclejava.crypto;

/**
 * 自描述密文信封：携带版本号、随机 IV 与密文（含认证标签）。
 * 线上编码格式由 CipherCodec 负责。
 */
public record CiphertextEnvelope(
        int keyVersion,
        byte[] iv,
        byte[] cipherText
) {
}
