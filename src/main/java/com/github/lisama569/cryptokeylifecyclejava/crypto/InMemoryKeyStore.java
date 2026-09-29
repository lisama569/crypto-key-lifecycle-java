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
    public synchronized Optional<KeyVersion> find(int version) {
        return Optional.ofNullable(entries.get(version)).map(Entry::meta);
    }

    @Override
    public Optional<SecretKey> findKey(int version) {
        return Optional.ofNullable(entries.get(version)).map(Entry::key);
    }

    @Override
    public synchronized Optional<KeyVersion> current() {
        return entries.values().stream()
                .map(Entry::meta)
                .filter(m -> m.state() == KeyState.ACTIVE)
                .findFirst();
    }

    @Override
    public synchronized List<KeyVersion> all() {
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
    public synchronized void removeIfPending(int version) {
        Entry entry = entries.get(version);
        if (entry != null && entry.meta().state() == KeyState.PENDING) {
            entries.remove(version);
        }
    }

    /**
     * 在同一把锁、同一次更新内完成“新版本 PENDING→ACTIVE + 旧版本 ACTIVE→RETIRED”。
     * 先做全部校验、构造全部新 Entry，最后才依次替换：由于读路径（{@link #current()}、
     * {@link #find(int)}、{@link #all()}）都持有同一把 monitor，外部读者不可能看到
     * 两次替换之间的中间状态，因此任何时刻系统里都恰好有一个 ACTIVE——
     * 轮换期间不会出现“没有可用版本”的窗口。
     */
    @Override
    public synchronized void activateAndRetire(KeyVersion newActive, Integer retiredVersion) {
        if (newActive == null || newActive.state() != KeyState.ACTIVE) {
            throw new IllegalArgumentException("newActive must be an ACTIVE KeyVersion");
        }
        Entry newEntry = entries.get(newActive.version());
        if (newEntry == null) {
            throw new IllegalStateException(
                    "key version " + newActive.version() + " does not exist");
        }
        if (newEntry.meta().state() != KeyState.PENDING) {
            throw new IllegalStateException("key version " + newActive.version()
                    + " is not PENDING but " + newEntry.meta().state());
        }
        Entry retiredEntry = null;
        KeyVersion retiredMeta = null;
        if (retiredVersion != null) {
            retiredEntry = entries.get(retiredVersion);
            if (retiredEntry == null) {
                throw new IllegalStateException(
                        "key version " + retiredVersion + " does not exist");
            }
            if (retiredEntry.meta().state() != KeyState.ACTIVE) {
                throw new IllegalStateException("key version " + retiredVersion
                        + " is not ACTIVE but " + retiredEntry.meta().state());
            }
            retiredMeta = new KeyVersion(retiredVersion, KeyState.RETIRED,
                    retiredEntry.meta().createdAt(), java.time.Instant.now(),
                    retiredEntry.meta().revokedAt());
        }
        // 校验全部通过后才提交。两次写入都在本 monitor 内，读路径（current/find/all）
        // 持同一把锁，因此“旧已 RETIRED、新未 ACTIVE”的零 ACTIVE 瞬间对外不可见。
        // 顺序为“先退休旧版本、再启用新版本”：一旦提交过程中失败，可以直接把旧版本
        // Entry 原样写回（仍在同一临界区内）完成存储层自愈，monitor 释放后读者看到的
        // 要么是完整的切换前状态，要么是完整的切换后状态，绝不会看到零 ACTIVE。
        Entry previousActiveEntry = retiredEntry;
        if (retiredEntry != null) {
            entries.put(retiredVersion, new Entry(retiredMeta, retiredEntry.key()));
        }
        try {
            betweenSwitchPuts(newActive, retiredVersion);
            entries.put(newActive.version(), new Entry(newActive, newEntry.key()));
        } catch (RuntimeException commitError) {
            // 提交失败：在释放 monitor 前把旧版本原样恢复，杜绝“没有可用版本”窗口
            if (previousActiveEntry != null) {
                entries.put(retiredVersion, previousActiveEntry);
            }
            throw commitError;
        }
    }

    /**
     * 两次状态写入之间的接缝（仍持有本存储 monitor）：默认无操作。
     * 仅供测试在“旧版本已 RETIRED、新版本尚未 ACTIVE”的临界瞬间插入栅栏/故障，
     * 以确定性地验证任何外部读者都观察不到该中间态、且失败时存储层会自愈。
     */
    protected void betweenSwitchPuts(KeyVersion newActive, Integer retiredVersion) {
        // no-op
    }
}
