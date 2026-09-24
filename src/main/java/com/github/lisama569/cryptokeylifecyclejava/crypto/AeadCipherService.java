package com.github.lisama569.cryptokeylifecyclejava.crypto;

import com.github.lisama569.cryptokeylifecyclejava.config.KeyLifecycleProperties;
import com.github.lisama569.cryptokeylifecyclejava.error.IntegrityVerificationException;
import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 基于 AES/GCM 的认证加密服务。
 *
 * <ul>
 *   <li>每次加密生成随机 IV；密钥版本号作为 AAD 参与认证，篡改版本头同样判定完整性失败；</li>
 *   <li>线路编码 {@code v1:<version> b64url(iv).b64url(ciphertext||tag)}，全部为可打印 ASCII；</li>
 *   <li>解码阶段的格式问题报 INVALID_INPUT；解密阶段的标签失败报 INTEGRITY_FAILURE，二者可区分；</li>
 *   <li>异常文案不包含明文或密钥材料。</li>
 * </ul>
 */
@Component
public class AeadCipherService {

    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final String HEADER_PREFIX = "v1:";
    private static final char HEADER_SEPARATOR = ' ';
    private static final byte SEGMENT_SEPARATOR = '.';

    private final SecureRandom secureRandom = new SecureRandom();
    private final int ivLengthBytes;
    private final int tagLengthBits;

    public AeadCipherService(KeyLifecycleProperties properties) {
        this.ivLengthBytes = properties.getGcmIvLengthBytes();
        this.tagLengthBits = properties.getGcmTagLengthBits();
    }

    /** 使用给定密钥版本生成新 IV 并加密明文。 */
    public CipherPayload encrypt(KeyVersion key, byte[] plaintext) {
        if (key == null) {
            throw new InvalidInputException("key version is required");
        }
        if (plaintext == null) {
            throw new InvalidInputException("plaintext is required");
        }
        try {
            byte[] iv = new byte[ivLengthBytes];
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), new GCMParameterSpec(tagLengthBits, iv));
            cipher.updateAAD(aad(key.getVersion()));
            byte[] ciphertextWithTag = cipher.doFinal(plaintext);
            return new CipherPayload(key.getVersion(), iv, ciphertextWithTag);
        } catch (GeneralSecurityException e) {
            // 不应发生（密钥由本系统生成）；保守按完整性失败处理且不泄露细节
            throw new IntegrityVerificationException("encryption failed for version " + key.getVersion(), e);
        }
    }

    /** 使用给定密钥版本解密；认证失败时抛出 IntegrityVerificationException。 */
    public byte[] decrypt(KeyVersion key, CipherPayload payload) {
        if (key == null || payload == null) {
            throw new InvalidInputException("key and payload are required");
        }
        if (key.getVersion() != payload.getKeyVersion()) {
            // 密文自称的版本与解密密钥不一致：视为被篡改
            throw new IntegrityVerificationException(
                    "payload version does not match key version: payload=" + payload.getKeyVersion());
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(),
                    new GCMParameterSpec(tagLengthBits, payload.getIv()));
            cipher.updateAAD(aad(key.getVersion()));
            return cipher.doFinal(payload.getCiphertextWithTag());
        } catch (GeneralSecurityException e) {
            // AEADBadTagException 等统一映射为完整性失败，不回退、不返回任何明文
            throw new IntegrityVerificationException(
                    "authentication failed for version " + key.getVersion(), e);
        }
    }

    /** 将密文载体编码为可存储/传输的字符串。 */
    public String encode(CipherPayload payload) {
        if (payload == null || payload.getIv() == null || payload.getCiphertextWithTag() == null) {
            throw new InvalidInputException("payload is incomplete");
        }
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return HEADER_PREFIX + payload.getKeyVersion() + HEADER_SEPARATOR
                + encoder.encodeToString(payload.getIv())
                + (char) SEGMENT_SEPARATOR
                + encoder.encodeToString(payload.getCiphertextWithTag());
    }

    /** 解析字符串为密文载体；格式错误以 INVALID_INPUT 拒绝。 */
    public CipherPayload decode(String encoded) {
        if (encoded == null) {
            throw new InvalidInputException("cipher text is required");
        }
        byte[] raw;
        try {
            raw = encoded.getBytes(StandardCharsets.US_ASCII);
        } catch (Exception e) {
            throw new InvalidInputException("cipher text must be ASCII");
        }
        byte[] prefix = HEADER_PREFIX.getBytes(StandardCharsets.US_ASCII);
        if (raw.length < prefix.length + 2) {
            throw new InvalidInputException("cipher text is too short");
        }
        for (int i = 0; i < prefix.length; i++) {
            if (raw[i] != prefix[i]) {
                throw new InvalidInputException("unsupported cipher text header");
            }
        }
        int sep = indexOf(raw, (byte) HEADER_SEPARATOR, prefix.length - 1);
        if (sep < 0) {
            throw new InvalidInputException("missing key version separator");
        }
        int dot = indexOf(raw, SEGMENT_SEPARATOR, sep + 1);
        if (dot < 0 || indexOf(raw, SEGMENT_SEPARATOR, dot + 1) >= 0) {
            throw new InvalidInputException("cipher text must contain iv.ciphertext segments");
        }
        int version;
        try {
            version = Integer.parseInt(new String(raw, prefix.length, sep - prefix.length, StandardCharsets.US_ASCII));
        } catch (NumberFormatException e) {
            throw new InvalidInputException("key version is not a number");
        }
        if (version <= 0) {
            throw new InvalidInputException("key version must be positive");
        }
        byte[] iv;
        byte[] ciphertextWithTag;
        try {
            Base64.Decoder decoder = Base64.getUrlDecoder();
            iv = decoder.decode(new String(raw, sep + 1, dot - sep - 1, StandardCharsets.US_ASCII));
            ciphertextWithTag = decoder.decode(
                    new String(raw, dot + 1, raw.length - dot - 1, StandardCharsets.US_ASCII));
        } catch (IllegalArgumentException e) {
            throw new InvalidInputException("cipher text is not valid base64url");
        }
        if (iv.length != ivLengthBytes) {
            throw new InvalidInputException("unexpected iv length");
        }
        if (ciphertextWithTag.length <= tagLengthBits / 8) {
            throw new InvalidInputException("ciphertext segment is too short");
        }
        return new CipherPayload(version, iv, ciphertextWithTag);
    }

    private static byte[] aad(int version) {
        return (HEADER_PREFIX + version).getBytes(StandardCharsets.US_ASCII);
    }

    private static int indexOf(byte[] data, byte target, int from) {
        for (int i = Math.max(from, 0); i < data.length; i++) {
            if (data[i] == target) {
                return i;
            }
        }
        return -1;
    }
}
