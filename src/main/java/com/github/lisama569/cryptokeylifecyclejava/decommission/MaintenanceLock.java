package com.github.lisama569.cryptokeylifecyclejava.decommission;

import java.util.concurrent.locks.ReentrantLock;

/**
 * 数据维护操作共享锁：历史数据迁移（全量/定向清理）与安全下线共用同一把锁。
 *
 * <p>它保证“引用清零判定 + 版本状态切换”作为整体，与数据改写互斥，
 * 从而不会出现版本已下线但历史数据仍指向它的结果。
 */
public final class MaintenanceLock {

    private final ReentrantLock lock = new ReentrantLock();

    public void lock() {
        lock.lock();
    }

    public void unlock() {
        lock.unlock();
    }
}
