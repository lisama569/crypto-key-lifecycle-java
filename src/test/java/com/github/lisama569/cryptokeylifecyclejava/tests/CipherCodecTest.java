package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CiphertextEnvelope;
import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 密文信封编解码：自描述版本号、往返一致、畸形输入拒绝。 */
class CipherCodecTest {

    private static final Logger log = LoggerFactory.getLogger(CipherCodecTest.class);

    private final CipherCodec codec = new CipherCodec();
    private final AesGcmCipher cipher = new AesGcmCipher(12, 128);

    @Test
    void encodeDecodeRoundTrips() {
        CiphertextEnvelope env = cipher.encrypt(AesGcmCipher.generateKey(256), 7,
                "payload".getBytes(StandardCharsets.UTF_8));
        String encoded = codec.encode(env);
        CiphertextEnvelope decoded = codec.decode(encoded);

        assertEquals(7, decoded.keyVersion());
        assertArrayEquals(env.iv(), decoded.iv());
        assertArrayEquals(env.cipherText(), decoded.cipherText());
        assertTrue(encoded.startsWith("v7:"));
        log.info("[codec] version=7 op=ROUND_TRIP basis=VERSION_PREFIXED_ENVELOPE format={} result=PASS",
                encoded.substring(0, encoded.indexOf(':')));
    }

    @Test
    void malformedInputsAreRejectedWithDistinguishableReason() {
        String[] bad = {null, "", "   ", "abc", "v1", "1:aa:bb", "vx:aa:bb", "v0:aa:bb",
                "v1::", "v1:aa:", "v1:##:bb", "v1:aa:!!", "v1:a:b", "v 1:aa:bb"};
        for (String input : bad) {
            InvalidInputException ex = assertThrows(InvalidInputException.class,
                    () -> codec.decode(input));
            assertEquals("INVALID_INPUT", ex.reasonCode());
            log.warn("[codec] version=N/A op=DECODE input='{}' basis=MALFORMED_ENVELOPE reason={} result=REJECTED",
                    input, ex.reasonCode());
        }
    }

    @Test
    void versionIsExtractedBeforeDecryption() {
        CiphertextEnvelope env = cipher.encrypt(AesGcmCipher.generateKey(256), 42,
                "x".getBytes(StandardCharsets.UTF_8));
        String encoded = codec.encode(env);
        assertEquals(42, codec.decode(encoded).keyVersion());
        log.info("[codec] version=42 op=EXTRACT_VERSION basis=ENVELOPE_HEADER result=PASS");
    }
}
