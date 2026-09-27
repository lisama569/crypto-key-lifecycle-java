package com.github.lisama569.cryptokeylifecyclejava.lifecycle;

/**
 * 单个密钥版本的引用统计与安全下线预检结论（可序列化为 JSON）。
 *
 * @param version            密钥版本号
 * @param state              该版本当前生命周期状态
 * @param referenceCount     快照时刻仍引用该版本的数据记录条数
 * @param active             是否为当前正在提供服务的 ACTIVE 版本
 * @param safeToDecommission 当前是否可以安全下线
 * @param reason             判定依据：SAFE_TO_DECOMMISSION / BLOCKED_BY_REFERENCES /
 *                           BLOCKED_ACTIVE_VERSION / ALREADY_DECOMMISSIONED
 */
public record VersionReferenceStats(
        int version,
        String state,
        long referenceCount,
        boolean active,
        boolean safeToDecommission,
        String reason
) {
}
