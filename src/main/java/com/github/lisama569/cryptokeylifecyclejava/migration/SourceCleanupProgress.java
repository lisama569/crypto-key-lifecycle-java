package com.github.lisama569.cryptokeylifecyclejava.migration;

/**
 * 一次按来源版本定向清理的进度快照，可核验、可序列化（JSON 输出）。
 *
 * @param fromVersion 被定向清理的来源版本
 * @param toVersion   目标（当前启用）版本
 * @param sourceTotal 快照时刻仍停留在来源版本的记录条数（本批处理前）
 * @param migrated    本批新迁移成功的条数
 * @param skipped     本批幂等跳过的条数（已被并发迁移）
 * @param failed      本批失败的条数（原密文保留，不被破坏）
 * @param remaining   快照时刻仍停留在来源版本的记录条数（本批处理后，实时扫描得出）
 * @param completed   来源版本的引用是否已收敛为零
 */
public record SourceCleanupProgress(
        int fromVersion,
        int toVersion,
        int sourceTotal,
        int migrated,
        int skipped,
        int failed,
        int remaining,
        boolean completed
) {
    /** 0.0 ~ 100.0 的来源版本清理完成百分比，空来源集视为 100%。 */
    public double percent() {
        if (sourceTotal == 0) {
            return 100.0;
        }
        long done = sourceTotal - remaining;
        return Math.round(done * 1000.0 / sourceTotal) / 10.0;
    }
}
