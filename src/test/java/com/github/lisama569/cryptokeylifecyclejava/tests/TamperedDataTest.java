package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.error.IntegrityVerificationException;
import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRecord;
import com.github.lisama569.cryptokeylifecyclejava.migration.InMemoryDataRepository;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationService;
import com.github.lisama569.cryptokeylifecyclejava.migration.RecordStatus;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 数据篡改场景：字节翻转、信封损坏、迁移中遇篡改均被识别为完整性失败且不泄露明文。 */
class TamperedDataTest {

    private static final Logger log = LoggerFactory.getLogger(TamperedDataTest.class);

    private KeyManager newManager() {
        return new KeyManager(new InMemoryKeyStore(), new AesGcmCipher(12, 128),
                new CipherCodec(), 256);
    }

    /** 翻转 base64 密文段中部的一个字符，模拟存储层篡改。 */
    private String flipOneCipherChar(String encoded) {
        int lastColon = encoded.lastIndexOf(':');
        char[] chars = encoded.toCharArray();
        int pos = lastColon + 2;
        chars[pos] = chars[pos] == 'A' ? 'B' : 'A';
        return new String(chars);
    }

    @Test
    void tamperedStoredCiphertextIsRejectedWithIntegrityReason() {
        KeyManager km = newManager();
        km.generateAndActivate();
        String original = km.encrypt("账户余额:9999");
        String tampered = flipOneCipherChar(original);

        IntegrityVerificationException ex = assertThrows(IntegrityVerificationException.class,
                () -> km.decrypt(tampered));
        assertEquals("INTEGRITY_FAILURE", ex.reasonCode());

        // 未被篡改的数据仍可正常解密：服务未受影响
        assertEquals("账户余额:9999", km.decrypt(original));
        log.warn("[tamper] version=1 op=DECRYPT basis=STORED_BYTES_FLIPPED reason={} result=REJECTED",
                ex.reasonCode());
    }

    @Test
    void tamperedRecordFailsMigrationButDoesNotCorruptOtherRecords() {
        KeyManager km = newManager();
        InMemoryDataRepository repo = new InMemoryDataRepository();
        MigrationService migration = new MigrationService(km, repo);
        km.generateAndActivate();

        String goodCipher = km.encrypt("good-record");
        String badCipher = flipOneCipherChar(km.encrypt("bad-record"));
        repo.save(new DataRecord("good", goodCipher, 1, RecordStatus.CURRENT));
        repo.save(new DataRecord("bad", badCipher, 1, RecordStatus.CURRENT));
        km.rotate();

        var progress = migration.migrateToCurrent(null);
        assertEquals(1, progress.migrated());
        assertEquals(1, progress.failed());
        assertFalse(progress.completed());

        // 被篡改记录原样保留（版本与密文未变），好记录成功迁移且明文不变
        DataRecord bad = repo.findById("bad").orElseThrow();
        assertEquals(1, bad.keyVersion());
        assertEquals(badCipher, bad.ciphertext());
        DataRecord good = repo.findById("good").orElseThrow();
        assertEquals(2, good.keyVersion());
        assertEquals("good-record", km.decrypt(good.ciphertext()));
        log.warn("[tamper] version=1->2 op=MIGRATE basis=ONE_RECORD_TAG_MISMATCH migrated={} failed={} result=ISOLATED",
                progress.migrated(), progress.failed());
    }

    @Test
    void corruptedEnvelopeStringIsInvalidInputDistinctFromIntegrityFailure() {
        KeyManager km = newManager();
        km.generateAndActivate();
        // 信封结构损坏（无法解析）与“可解析但标签错误”必须是两种不同原因
        InvalidInputException ex = assertThrows(InvalidInputException.class,
                () -> km.decrypt("not-an-envelope"));
        assertEquals("INVALID_INPUT", ex.reasonCode());
        log.warn("[tamper] version=N/A op=DECRYPT basis=ENVELOPE_UNPARSEABLE reason={} result=REJECTED",
                ex.reasonCode());
    }
}
