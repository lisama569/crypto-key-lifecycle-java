package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CiphertextEnvelope;
import com.github.lisama569.cryptokeylifecyclejava.error.IntegrityVerificationException;
import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** AES/GCM 原语：往返一致性、随机 IV、篡改检测。 */
class AesGcmCipherTest {

    private static final Logger log = LoggerFactory.getLogger(AesGcmCipherTest.class);

    private final AesGcmCipher cipher = new AesGcmCipher(12, 128);

    @Test
    void encryptThenDecryptRoundTrips() {
        SecretKey key = AesGcmCipher.generateKey(256);
        byte[] plaintext = "订单号-2026-0001-金额$42".getBytes(StandardCharsets.UTF_8);

        CiphertextEnvelope env = cipher.encrypt(key, 1, plaintext);
        byte[] recovered = cipher.decrypt(key, env);

        assertArrayEquals(plaintext, recovered);
        log.info("[cipher] version=1 op=ROUND_TRIP basis=AES_GCM_RANDOM_IV result=PASS");
    }

    @Test
    void twoEncryptionsProduceDifferentCiphertextBecauseOfRandomIv() {
        SecretKey key = AesGcmCipher.generateKey(256);
        byte[] plaintext = "same-plaintext".getBytes(StandardCharsets.UTF_8);

        CiphertextEnvelope a = cipher.encrypt(key, 1, plaintext);
        CiphertextEnvelope b = cipher.encrypt(key, 1, plaintext);

        assertFalse(a.iv() == b.iv());
        assertNotEquals(HexFormat.of().formatHex(a.iv()), HexFormat.of().formatHex(b.iv()));
        assertNotEquals(HexFormat.of().formatHex(a.cipherText()), HexFormat.of().formatHex(b.cipherText()));
        log.info("[cipher] version=1 op=ENCRYPT_TWICE basis=RANDOM_IV result=PASS ivA={} ivB={}",
                HexFormat.of().formatHex(a.iv()), HexFormat.of().formatHex(b.iv()));
    }

    @Test
    void tamperedCipherTextIsRejectedAsIntegrityFailure() {
        SecretKey key = AesGcmCipher.generateKey(256);
        byte[] plaintext = "sensitive".getBytes(StandardCharsets.UTF_8);
        CiphertextEnvelope env = cipher.encrypt(key, 1, plaintext);

        byte[] tampered = env.cipherText().clone();
        tampered[0] ^= 0x01; // 翻转一个密文字节
        CiphertextEnvelope corrupted = new CiphertextEnvelope(1, env.iv(), tampered);

        IntegrityVerificationException ex = assertThrows(IntegrityVerificationException.class,
                () -> cipher.decrypt(key, corrupted));
        assertEquals("INTEGRITY_FAILURE", ex.reasonCode());
        log.warn("[cipher] version=1 op=DECRYPT_TAMPERED basis=GCM_TAG_MISMATCH reason={} result=REJECTED",
                ex.reasonCode());
    }

    @Test
    void tamperedIvIsRejectedAsIntegrityFailure() {
        SecretKey key = AesGcmCipher.generateKey(256);
        CiphertextEnvelope env = cipher.encrypt(key, 1, "data".getBytes(StandardCharsets.UTF_8));

        byte[] badIv = env.iv().clone();
        badIv[0] ^= (byte) 0xFF;
        CiphertextEnvelope corrupted = new CiphertextEnvelope(1, badIv, env.cipherText());

        assertThrows(IntegrityVerificationException.class, () -> cipher.decrypt(key, corrupted));
        log.warn("[cipher] version=1 op=DECRYPT_TAMPERED_IV basis=GCM_TAG_MISMATCH result=REJECTED");
    }

    @Test
    void decryptWithWrongKeyIsIntegrityFailure() {
        CiphertextEnvelope env = cipher.encrypt(AesGcmCipher.generateKey(256), 1,
                "data".getBytes(StandardCharsets.UTF_8));
        SecretKey other = AesGcmCipher.generateKey(256);
        assertThrows(IntegrityVerificationException.class, () -> cipher.decrypt(other, env));
        log.warn("[cipher] version=1 op=DECRYPT_WRONG_KEY basis=GCM_TAG_MISMATCH result=REJECTED");
    }

    @Test
    void invalidInputsAreRejectedWithoutServiceImpact() {
        SecretKey key = AesGcmCipher.generateKey(256);
        assertThrows(InvalidInputException.class, () -> cipher.encrypt(key, 1, null));
        assertThrows(InvalidInputException.class, () -> cipher.encrypt(null, 1, new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> AesGcmCipher.generateKey(123));
        // 拒绝后服务仍可正常工作
        assertArrayEquals("ok".getBytes(StandardCharsets.UTF_8),
                cipher.decrypt(key, cipher.encrypt(key, 1, "ok".getBytes(StandardCharsets.UTF_8))));
        log.info("[cipher] version=1 op=INVALID_INPUT basis=INPUT_VALIDATION result=REJECTED_AND_SERVICE_ALIVE");
    }
}
