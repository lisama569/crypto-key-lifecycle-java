package com.github.lisama569.cryptokeylifecyclejava.migration;

/**
 * 一次历史数据迁移的进度快照，可核验、可序列化（JSON 输出）。
 *
 * @param fromVersion 本批扫描到的最旧来源版本（没有旧版本记录时等于 toVersion）
 * @param toVersion   目标（当前启用）版本
 * @param total       数据总条数
 * @param migrated    本批新迁移成功的条数
 * @param skipped     本批幂等跳过的条数（已是目标版本/已被并发迁移）
 * @param failed      本批失败的条数（原密文保留，不被破坏）
 * @param remaining   快照时刻仍停留在旧版本的记录条数
 * @param completed   是否已经没有残留旧版本记录
 */
public record MigrationProgress(
        int fromVersion,
        int toVersion,
        int total,
        int migrated,
        int skipped,
        int failed,
        int remaining,
        boolean completed
) {
    /** 0.0 ~ 100.0 的完成百分比，空数据集视为 100%。 */
    public double percent() {
        if (total == 0) {
            return 100.0;
        }
        long onTarget = total - remaining;
        return Math.round(onTarget * 1000.0 / total) / 10.0;
    }
}
