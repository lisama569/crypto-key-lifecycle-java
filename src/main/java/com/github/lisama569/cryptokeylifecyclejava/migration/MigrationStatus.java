package com.github.lisama569.cryptokeylifecyclejava.migration;

/**
 * 一次历史迁移的生命周期状态。
 *
 * <pre>
 * RUNNING ──本批处理完仍有剩余──▶ PAUSED（可凭 migrationId 续跑）
 * RUNNING ──全部处理完且无冲突──▶ COMPLETED
 * RUNNING ──出现冲突/解密失败──▶ FAILED（已迁移部分不回滚，仍可续跑/重跑修复）
 * </pre>
 */
public enum MigrationStatus {
    RUNNING,
    PAUSED,
    COMPLETED,
    FAILED
}
