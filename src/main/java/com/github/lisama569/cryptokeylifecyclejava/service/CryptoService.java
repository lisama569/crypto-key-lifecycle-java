package com.github.lisama569.cryptokeylifecyclejava.service;

import com.github.lisama569.cryptokeylifecyclejava.audit.AuditLogger;
import com.github.lisama569.cryptokeylifecyclejava.crypto.AeadCipherService;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherPayload;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.KeyLifecycleManager;
import com.github.lisama569.cryptokeylifecyclejava.storage.EncryptedRecord;
import com.github.lisama569.cryptokeylifecyclejava.storage.EncryptedRecordStore;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

/**
 * 应用加解密门面。
 *
 * <ul>
 *   <li>加密永远只使用当前 ENABLED 版本：在生命周期读锁内取版本并完成加密，
 *       与轮换线性一致，轮换进行中的请求要么全部用旧版本、要么全部用新版本；</li>
 *   <li>解密按密文自带版本找密钥：ENABLED 可解、RETIRED 在版本保留期内可解，
 *       UNKNOWN/REVOKED/CREATED 一律拒绝且原因可区分；</li>
 *   <li>密文或版本头被篡改时 GCM 校验失败，抛 INTEGRITY_FAILURE，绝不返回错误明文。</li>
 * </ul>
 */
@Service
public class CryptoService {

    private static final int MAX_PLAINTEXT_BYTES = 1 << 20; // 1 MiB 防御性上限

    private final KeyLifecycleManager keyLifecycleManager;
    private final AeadCipherService cipherService;
    private final EncryptedRecordStore recordStore;
    private final AuditLogger auditLogger;

    public CryptoService(KeyLifecycleManager keyLifecycleManager,
                         AeadCipherService cipherService,
                         EncryptedRecordStore recordStore,
                         AuditLogger auditLogger) {
        this.keyLifecycleManager = keyLifecycleManager;
        this.cipherService = cipherService;
        this.recordStore = recordStore;
        this.auditLogger = auditLogger;
    }

    /** 加密明文并存储为一条记录。 */
    public EncryptedRecord encrypt(String id, String plaintext) {
        String encoded = encryptTransient(plaintext);
        int version = cipherService.decode(encoded).getKeyVersion();
        EncryptedRecord record = recordStore.create(id, version, encoded);
        auditLogger.log("ENCRYPT", version, "ALLOWED", "stored record " + id);
        return record;
    }

    /** 解密指定记录。 */
    public String decrypt(String id) {
        EncryptedRecord record = recordStore.require(id);
        return decryptTransient(record.getCipherText());
    }

    /** 无存储的纯加密：只使用当前 ENABLED 版本。 */
    public String encryptTransient(String plaintext) {
        if (plaintext == null) {
            throw new InvalidInputException("plaintext is required");
        }
        byte[] raw = plaintext.getBytes(StandardCharsets.UTF_8);
        if (raw.length == 0) {
            throw new InvalidInputException("plaintext must not be empty");
        }
        if (raw.length > MAX_PLAINTEXT_BYTES) {
            throw new InvalidInputException("plaintext exceeds size limit");
        }
        // 读锁覆盖“取当前版本 + 加密”：期间轮换无法提交，保证只用启用版本
        return keyLifecycleManager.withReadLock(() -> {
            KeyVersion current = keyLifecycleManager.currentVersion();
            CipherPayload payload = cipherService.encrypt(current, raw);
            return cipherService.encode(payload);
        });
    }

    /**
     * 测试/迁移辅助：用指定（已存在）版本的密钥加密，返回线路编码密文。
     * 不改变任何状态，供确定性并发测试构造“同版本不同密文”的重写场景。
     */
    public String encryptWithVersion(int version, String plaintext) {
        byte[] raw = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return keyLifecycleManager.withReadLock(() -> {
            KeyVersion key = keyLifecycleManager.requireVersion(version);
            CipherPayload payload = cipherService.encrypt(key, raw);
            return cipherService.encode(payload);
        });
    }

    /** 无存储的纯解密：按密文版本路由密钥。 */
    public String decryptTransient(String encoded) {
        CipherPayload payload = cipherService.decode(encoded); // 格式错误 -> INVALID_INPUT
        int version = payload.getKeyVersion();
        // 读锁覆盖“定位密钥 + 解密”，保证解密瞬间该版本未被吊销/更换
        byte[] plaintextBytes = keyLifecycleManager.withReadLock(() -> {
            KeyVersion key = keyLifecycleManager.requireVersionForDecrypt(version); // 吊销/未知在此拒绝
            return cipherService.decrypt(key, payload); // 标签失败 -> INTEGRITY_FAILURE
        });
        auditLogger.log("DECRYPT", version, "ALLOWED", "authenticated decryption");
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }
}
