package com.github.lisama569.cryptokeylifecyclejava.crypto;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKey;

/**
 * 线程安全的内存 {@link KeyStore}。
 *
 * <p>结构本身只提供线程安全的读写；跨“读当前—改状态—写回”的原子性由
 * {@link KeyManager} 内的生命周期锁保证。{@link #updateState(KeyVersion)}
 * 要求版本已存在，防止凭空写入状态。
 */
public class InMemoryKeyStore implements KeyStore {

    private record Entry(KeyVersion meta, SecretKey key) { }

    private final ConcurrentHashMap<Integer, Entry> entries = new ConcurrentHashMap<>();

    @Override
    public synchronized int nextVersion() {
        return entries.keySet().stream().max(Comparator.naturalOrder()).orElse(0) + 1;
    }

    @Override
    public synchronized void put(KeyVersion meta, SecretKey key) {
        if (meta == null || key == null) {
            throw new IllegalArgumentException("meta and key are required");
        }
        Entry existing = entries.get(meta.version());
        if (existing != null) {
            // 同一版本只允许写入一次密钥材料；后续状态变更走 updateState
            throw new IllegalStateException("key version " + meta.version() + " already exists");
        }
        entries.put(meta.version(), new Entry(meta, key));
    }

    @Override
    public Optional<KeyVersion> find(int version) {
        return Optional.ofNullable(entries.get(version)).map(Entry::meta);
    }

    @Override
    public Optional<SecretKey> findKey(int version) {
        return Optional.ofNullable(entries.get(version)).map(Entry::key);
    }

    @Override
    public Optional<KeyVersion> current() {
        return entries.values().stream()
                .map(Entry::meta)
                .filter(m -> m.state() == KeyState.ACTIVE)
                .findFirst();
    }

    @Override
    public List<KeyVersion> all() {
        List<KeyVersion> snapshot = new ArrayList<>(entries.size());
        entries.values().forEach(e -> snapshot.add(e.meta()));
        snapshot.sort(Comparator.comparingInt(KeyVersion::version));
        return List.copyOf(snapshot);
    }

    @Override
    public synchronized void updateState(KeyVersion meta) {
        if (meta == null) {
            throw new IllegalArgumentException("meta is required");
        }
        Entry existing = entries.get(meta.version());
        if (existing == null) {
            throw new IllegalStateException("key version " + meta.version() + " does not exist");
        }
        // 密钥材料不变，仅替换状态元数据
        entries.put(meta.version(), new Entry(meta, existing.key()));
    }

    @Override
    public synchronized void removeUnfinishedVersion(int version) {
        Entry entry = entries.get(version);
        if (entry != null && (entry.meta().state() == KeyState.PENDING
                || entry.meta().state() == KeyState.ACTIVE)) {
            entries.remove(version);
        }
    }
}
