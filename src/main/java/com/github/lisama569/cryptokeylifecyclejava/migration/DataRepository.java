package com.github.lisama569.cryptokeylifecyclejava.migration;

import java.util.List;
import java.util.Optional;

/** 业务数据存储抽象（本地、无外部服务）。 */
public interface DataRepository {
    void save(DataRecord record);
    Optional<DataRecord> findById(String id);
    List<DataRecord> findAll();
    /** 乐观状态更新：仅当记录当前状态等于 expectedStatus 时才写入新密文与新状态。 */
    boolean compareAndUpdateStatus(String id, String expectedStatus, String newStatus,
                                   String newCiphertext, int newKeyVersion);
}
