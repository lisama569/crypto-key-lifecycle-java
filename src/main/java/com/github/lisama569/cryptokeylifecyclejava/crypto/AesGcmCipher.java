package com.github.lisama569.cryptokeylifecyclejava.crypto;

import com.github.lisama569.cryptokeylifecyclejava.error.IntegrityVerificationException;
import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 基于 AES/GCM 的无状态加解密原语。
 *
 * <p>每次加密生成随机 IV（默认 12 字节），GCM 认证标签默认 128 bit。
 * 密钥与 IV 均不重复使用；篡改密文/IV/标签会在解密时抛出
 * {@link IntegrityVerificationException}，与“未知版本/已吊销”等失败原因可区分。
 */
public final class AesGcmCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final int ivLengthBytes;
    private final int tagLengthBits;

    public AesGcmCipher(int ivLengthBytes, int tagLengthBits) {
        if (ivLengthBytes <= 0) {
            throw new IllegalArgumentException("ivLengthBytes must be positive");
        }
        if (tagLengthBits <= 0 || tagLengthBits % 8 != 0) {
            throw new IllegalArgumentException("tagLengthBits must be a positive multiple of 8");
        }
        this.ivLengthBytes = ivLengthBytes;
        this.tagLengthBits = tagLengthBits;
    }

    /** 生成一个新的 AES 密钥（AES-128/192/256）。 */
    public static SecretKey generateKey(int keyBits) {
        if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
            throw new IllegalArgumentException("AES key size must be 128, 192 or 256 bits");
        }
        try {
            KeyGenerator generator = KeyGenerator.getInstance(KEY_ALGORITHM);
            generator.init(keyBits, RANDOM);
            return generator.generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES key generation unavailable in this JVM", e);
        }
    }

    /** 从已保存的原始字节重建密钥（不拷贝，仅本地持久化使用）。 */
    public static SecretKey restoreKey(byte[] raw) {
        if (raw == null || (raw.length != 16 && raw.length != 24 && raw.length != 32)) {
            throw new InvalidInputException("invalid AES key material length");
        }
        return new SecretKeySpec(raw, KEY_ALGORITHM);
    }

    /** 导出密钥原始字节（仅供本地持久化）。 */
    public static byte[] exportKey(SecretKey key) {
        try {
            return key.getEncoded();
        } catch (Exception e) {
            throw new InvalidInputException("key material is not exportable");
        }
    }

    public byte[] generateIv() {
        byte[] iv = new byte[ivLengthBytes];
        RANDOM.nextBytes(iv);
        return iv;
    }

    /**
     * 加密明文。永不返回 null；异常输入抛出 {@link InvalidInputException}，
     * 不向上游泄露除“非法输入”以外的任何信息。
     */
    public CiphertextEnvelope encrypt(SecretKey key, int keyVersion, byte[] plaintext) {
        if (key == null) {
            throw new InvalidInputException("encryption key is required");
        }
        if (plaintext == null) {
            throw new InvalidInputException("plaintext is required");
        }
        byte[] iv = generateIv();
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(tagLengthBits, iv));
            byte[] cipherText = cipher.doFinal(plaintext);
            return new CiphertextEnvelope(keyVersion, iv, cipherText);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("encryption failed: " + e.getClass().getSimpleName(), e);
        }
    }

    /**
     * 解密密文信封。GCM 标签校验失败（含任何字节级篡改）统一抛出
     * {@link IntegrityVerificationException}。
     */
    public byte[] decrypt(SecretKey key, CiphertextEnvelope envelope) {
        if (key == null) {
            throw new InvalidInputException("decryption key is required");
        }
        if (envelope == null || envelope.iv() == null || envelope.cipherText() == null) {
            throw new InvalidInputException("ciphertext envelope is incomplete");
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(tagLengthBits, envelope.iv()));
            return cipher.doFinal(envelope.cipherText());
        } catch (GeneralSecurityException e) {
            // AEADBadTagException 及其它解密失败一律视为完整性失败，不回显任何明文信息
            throw new IntegrityVerificationException(
                    "ciphertext integrity verification failed for key version " + envelope.keyVersion(), e);
        }
    }
}
