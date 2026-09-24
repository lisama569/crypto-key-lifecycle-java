package com.github.lisama569.cryptokeylifecyclejava.storage;

import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 内存加密记录存储。
 *
 * <ul>
 *   <li>ConcurrentHashMap 保证记录引用的原子可见；</li>
 *   <li>{@link #compareAndUpdate} 以 (版本,密文) 快照做乐观更新，防止迁移与普通写互相覆盖；</li>
 *   <li>snapshot 按 id 字典序返回，供迁移稳定扫描与进度核验。</li>
 * </ul>
 */
@Component
public class EncryptedRecordStore {

    private final ConcurrentHashMap<String, EncryptedRecord> records = new ConcurrentHashMap<>();
    private final AtomicLong clock = new AtomicLong(0);

    /** 新建记录；id 重复时以 INVALID_INPUT 拒绝。 */
    public EncryptedRecord create(String id, int keyVersion, String cipherText) {
        if (id == null || id.isBlank()) {
            throw new InvalidInputException("record id is required");
        }
        if (cipherText == null) {
            throw new InvalidInputException("cipher text is required");
        }
        EncryptedRecord record = new EncryptedRecord(id, keyVersion, cipherText, clock.incrementAndGet());
        if (records.putIfAbsent(id, record) != null) {
            throw new InvalidInputException("record id already exists: " + id);
        }
        return record;
    }

    public Optional<EncryptedRecord> find(String id) {
        if (id == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(records.get(id));
    }

    public EncryptedRecord require(String id) {
        return find(id).orElseThrow(() -> new InvalidInputException("record not found: " + id));
    }

    /**
     * CAS 更新：仅当记录当前 (keyVersion, cipherText) 与期望值一致时替换为新值。
     * 字段级校验 + 同步块双检，保证并发情况下只有一个更新成功，不会出现撕裂状态。
     *
     * @return 是否更新成功
     */
    public boolean compareAndUpdate(EncryptedRecord record,
                                    int expectedVersion,
                                    String expectedCipher,
                                    int newVersion,
                                    String newCipher) {
        if (record == null || newCipher == null) {
            throw new InvalidInputException("record and new cipher text are required");
        }
        synchronized (record) {
            if (record.getKeyVersion() != expectedVersion
                    || !java.util.Objects.equals(record.getCipherText(), expectedCipher)) {
                return false;
            }
            record.setKeyVersion(newVersion);
            record.setCipherText(newCipher);
            record.setUpdatedAt(clock.incrementAndGet());
            return true;
        }
    }

    /** 无条件覆盖（普通加密写路径），单条记录同步保证原子可见。 */
    public void replace(EncryptedRecord record, int newVersion, String newCipher) {
        if (record == null || newCipher == null) {
            throw new InvalidInputException("record and new cipher text are required");
        }
        synchronized (record) {
            record.setKeyVersion(newVersion);
            record.setCipherText(newCipher);
            record.setUpdatedAt(clock.incrementAndGet());
        }
    }

    /** 统计仍引用某密钥版本的记录数（用于吊销前置检查与迁移进度核验）。 */
    public long countByVersion(int keyVersion) {
        long count = 0;
        for (EncryptedRecord record : records.values()) {
            if (record.getKeyVersion() == keyVersion) {
                count++;
            }
        }
        return count;
    }

    /** 全量快照（按 id 字典序），用于迁移扫描与进度核验。 */
    public List<EncryptedRecord> snapshot() {
        List<EncryptedRecord> copy = List.copyOf(records.values());
        return copy.stream().sorted(Comparator.comparing(EncryptedRecord::getId)).toList();
    }

    public int size() {
        return records.size();
    }
}
