package com.github.lisama569.cryptokeylifecyclejava.crypto;

import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 密文信封的字符串编解码。
 *
 * <p>线上文本格式：{@code v<版本号>:<base64url(iv)>:<base64url(密文+标签)>}。
 * <ul>
 *   <li>自描述：携带密钥版本号，解密时可定位历史版本；</li>
 *   <li>定界明确：恰好两个冒号分隔三段，任何畸形输入抛 {@link InvalidInputException}；</li>
 *   <li>不含明文：编解码对象均为密文，异常信息不回显业务数据。</li>
 * </ul>
 */
public final class CipherCodec {

    private static final String PREFIX = "v";
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    public CipherCodec() { }

    public String encode(CiphertextEnvelope envelope) {
        if (envelope == null || envelope.iv() == null || envelope.cipherText() == null) {
            throw new InvalidInputException("cannot encode an incomplete ciphertext envelope");
        }
        if (envelope.keyVersion() < 1) {
            throw new InvalidInputException("ciphertext envelope carries an invalid key version");
        }
        return PREFIX + envelope.keyVersion()
                + ":" + ENCODER.encodeToString(envelope.iv())
                + ":" + ENCODER.encodeToString(envelope.cipherText());
    }

    public CiphertextEnvelope decode(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            throw new InvalidInputException("ciphertext is required");
        }
        // 限制长度，避免异常超长输入消耗资源
        if (encoded.length() > 1 << 24) {
            throw new InvalidInputException("ciphertext exceeds the allowed length");
        }
        int firstColon = encoded.indexOf(':');
        int lastColon = encoded.lastIndexOf(':');
        if (firstColon <= 1 || firstColon == lastColon) {
            throw new InvalidInputException("malformed ciphertext envelope");
        }
        String versionPart = encoded.substring(0, firstColon);
        if (!versionPart.startsWith(PREFIX)) {
            throw new InvalidInputException("ciphertext envelope must start with version prefix 'v'");
        }
        final int version;
        try {
            version = Integer.parseInt(versionPart.substring(1));
        } catch (NumberFormatException e) {
            throw new InvalidInputException("ciphertext envelope carries a non-numeric key version");
        }
        if (version < 1) {
            throw new InvalidInputException("ciphertext envelope carries an invalid key version");
        }
        byte[] iv = decodePart(encoded.substring(firstColon + 1, lastColon), "iv");
        byte[] cipherText = decodePart(encoded.substring(lastColon + 1), "ciphertext");
        if (iv.length == 0 || cipherText.length == 0) {
            throw new InvalidInputException("ciphertext envelope has empty iv or ciphertext");
        }
        return new CiphertextEnvelope(version, iv, cipherText);
    }

    private static byte[] decodePart(String part, String fieldName) {
        // Base64 URL 字母表之外的字符（含填充）由 decoder 直接拒绝
        try {
            byte[] bytes = DECODER.decode(part.getBytes(StandardCharsets.US_ASCII));
            if (bytes.length == 0) {
                throw new InvalidInputException("ciphertext envelope has empty " + fieldName);
            }
            return bytes;
        } catch (IllegalArgumentException e) {
            throw new InvalidInputException("ciphertext envelope has an illegal base64 " + fieldName);
        }
    }
}
