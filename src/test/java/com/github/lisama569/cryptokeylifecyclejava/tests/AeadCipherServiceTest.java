package com.github.lisama569.cryptokeylifecyclejava.tests;

import com.github.lisama569.cryptokeylifecyclejava.config.KeyLifecycleProperties;
import com.github.lisama569.cryptokeylifecyclejava.crypto.AeadCipherService;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherPayload;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.FailureReason;
import com.github.lisama569.cryptokeylifecyclejava.error.IntegrityVerificationException;
import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyLifecycleException;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.KeyState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AEAD 封装测试：往返一致、IV 随机性、密文篡改/版本头篡改 → INTEGRITY_FAILURE、
 * 畸形输入 → INVALID_INPUT，两类失败原因必须可区分。
 */
class AeadCipherServiceTest {

    private static final Logger testLog = LoggerFactory.getLogger("KEY_LIFECYCLE_TEST");

    private AeadCipherService cipherService;
    private KeyVersion keyV1;

    @BeforeEach
    void setUp() throws Exception {
        cipherService = new AeadCipherService(new KeyLifecycleProperties());
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        keyV1 = new KeyVersion(1, generator.generateKey(), Instant.now(), KeyState.ENABLED);
    }

    @Test
    @DisplayName("加密-解密往返：明文含义保持不变")
    void roundTrip() {
        String plain = "hello-key-lifecycle-密钥轮换";
        CipherPayload payload = cipherService.encrypt(keyV1, plain.getBytes(StandardCharsets.UTF_8));
        String encoded = cipherService.encode(payload);
        CipherPayload decoded = cipherService.decode(encoded);
        String result = new String(cipherService.decrypt(keyV1, decoded), StandardCharsets.UTF_8);
        testLog.info("op=ROUNDTRIP keyVersion=1 decision=ALLOWED reason='gcm authenticate success, plaintext preserved'");
        assertEquals(plain, result);
        assertTrue(encoded.startsWith("v1:1 "), "编码必须带版本头");
    }

    @Test
    @DisplayName("同一明文两次加密产生不同密文（随机 IV），且都能解")
    void randomIvProducesDifferentCiphertext() {
        byte[] plain = "same-input".getBytes(StandardCharsets.UTF_8);
        String c1 = cipherService.encode(cipherService.encrypt(keyV1, plain));
        String c2 = cipherService.encode(cipherService.encrypt(keyV1, plain));
        assertNotEquals(c1, c2, "随机 IV 下密文必须不同");
        assertEquals("same-input",
                new String(cipherService.decrypt(keyV1, cipherService.decode(c1)), StandardCharsets.UTF_8));
        assertEquals("same-input",
                new String(cipherService.decrypt(keyV1, cipherService.decode(c2)), StandardCharsets.UTF_8));
        testLog.info("op=ENCRYPT keyVersion=1 decision=ALLOWED reason='random iv yields distinct ciphertexts'");
    }

    @Test
    @DisplayName("篡改密文正文 → INTEGRITY_FAILURE，不返回错误明文")
    void tamperedCiphertextRejected() {
        String encoded = cipherService.encode(
                cipherService.encrypt(keyV1, "secret-value".getBytes(StandardCharsets.UTF_8)));
        int dot = encoded.indexOf('.');
        String cipherSegment = encoded.substring(dot + 1);
        // 在 URL-safe base64 字母表内替换一个字符：格式仍然合法，GCM 标签必然校验失败
        int pos = cipherSegment.length() > 4 ? 2 : 0;
        char original = cipherSegment.charAt(pos);
        char flipped = original == 'A' ? 'B' : 'A';
        String tampered = encoded.substring(0, dot + 1)
                + cipherSegment.substring(0, pos) + flipped + cipherSegment.substring(pos + 1);

        IntegrityVerificationException ex = assertThrows(IntegrityVerificationException.class,
                () -> cipherService.decrypt(keyV1, cipherService.decode(tampered)));
        assertEquals(FailureReason.INTEGRITY_FAILURE, ex.getReason());
        assertFalse(ex.getMessage().contains("secret-value"), "异常文案不得包含明文");
        testLog.info("op=DECRYPT keyVersion=1 decision=REJECTED reason='{}'", ex.getReason());
    }

    @Test
    @DisplayName("篡改版本头（v1:1 改成 v1:2）→ 完整性失败（AAD 绑定版本）")
    void tamperedVersionHeaderRejected() {
        String encoded = cipherService.encode(
                cipherService.encrypt(keyV1, "secret-value".getBytes(StandardCharsets.UTF_8)));
        String tampered = encoded.replace("v1:1 ", "v1:2 ");
        KeyLifecycleException ex = assertThrows(KeyLifecycleException.class,
                () -> cipherService.decrypt(keyV1, cipherService.decode(tampered)));
        assertEquals(FailureReason.INTEGRITY_FAILURE, ex.getReason());
        testLog.info("op=DECRYPT keyVersion=2 decision=REJECTED reason='{} (aad version mismatch)'", ex.getReason());
    }

    @Test
    @DisplayName("用错误密钥解密 → INTEGRITY_FAILURE")
    void wrongKeyRejected() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        KeyVersion other = new KeyVersion(1, generator.generateKey(), Instant.now(), KeyState.ENABLED);
        CipherPayload payload = cipherService.encrypt(keyV1, "secret".getBytes(StandardCharsets.UTF_8));
        assertThrows(IntegrityVerificationException.class, () -> cipherService.decrypt(other, payload));
        testLog.info("op=DECRYPT keyVersion=1 decision=REJECTED reason='INTEGRITY_FAILURE (wrong key)'");
    }

    @Test
    @DisplayName("畸形/截断/非法 Base64 密文 → INVALID_INPUT，与完整性失败可区分")
    void malformedInputsRejectedAsInvalidInput() {
        assertInvalidInput(null);
        assertInvalidInput("");
        assertInvalidInput("garbage");
        assertInvalidInput("v1:1 abc");
        assertInvalidInput("v1:x YWE=.YWE=");
        assertInvalidInput("v1:1 ###.###");
        testLog.info("op=DECODE keyVersion=- decision=REJECTED reason='INVALID_INPUT (malformed payload)'");
    }

    @Test
    @DisplayName("null 明文/null 密钥 → INVALID_INPUT，异常输入不产生 NPE")
    void nullArgumentsRejected() {
        assertThrows(InvalidInputException.class,
                () -> cipherService.encrypt(keyV1, null));
        assertThrows(InvalidInputException.class,
                () -> cipherService.encrypt(null, new byte[1]));
        testLog.info("op=ENCRYPT keyVersion=- decision=REJECTED reason='INVALID_INPUT (null arguments)'");
    }

    private void assertInvalidInput(String encoded) {
        KeyLifecycleException ex = assertThrows(KeyLifecycleException.class,
                () -> cipherService.decode(encoded));
        assertEquals(FailureReason.INVALID_INPUT, ex.getReason(),
                "畸形密文应判 INVALID_INPUT，实际为 " + ex.getReason());
    }

}
