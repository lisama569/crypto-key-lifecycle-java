package com.github.lisama569.cryptokeylifecyclejava.migration;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 线程安全的内存 {@link DataRepository}。
 *
 * <p>{@link #compareAndUpdateStatus} 使用记录级锁做状态比较与写入的原子切换，
 * 是迁移“幂等、无冲突状态”的基础：只有当前状态符合预期的记录才会被改写。
 */
public class InMemoryDataRepository implements DataRepository {

    private final ConcurrentHashMap<String, DataRecord> records = new ConcurrentHashMap<>();

    @Override
    public void save(DataRecord record) {
        if (record == null || record.id() == null || record.id().isBlank()) {
            throw new IllegalArgumentException("record and its id are required");
        }
        records.put(record.id(), record);
    }

    @Override
    public Optional<DataRecord> findById(String id) {
        return Optional.ofNullable(records.get(id));
    }

    @Override
    public List<DataRecord> findAll() {
        List<DataRecord> snapshot = new ArrayList<>(records.size());
        snapshot.addAll(records.values());
        return List.copyOf(snapshot);
    }

    @Override
    public boolean compareAndUpdateStatus(String id, String expectedStatus, String newStatus,
                                          String newCiphertext, int newKeyVersion) {
        DataRecord existing = records.get(id);
        if (existing == null) {
            return false;
        }
        synchronized (existing) {
            DataRecord current = records.get(id);
            if (current == null || !current.status().equals(expectedStatus)) {
                return false;
            }
            records.put(id, new DataRecord(id, newCiphertext, newKeyVersion, newStatus));
            return true;
        }
    }
}
