package com.github.lisama569.cryptokeylifecyclejava.migration;

/**
 * 按来源版本定向清理一批数据的进度快照。
 *
 * @param fromVersion 指定清理的来源版本
 * @param toVersion   目标（当前启用）版本
 * @param total       该来源版本在批开始时的剩余条数
 * @param migrated    本批成功重加密条数
 * @param skipped     本批幂等跳过条数（已在目标版本/被并发处理）
 * @param failed      本批失败条数（如来源版本已吊销，原密文保留）
 * @param remaining   快照时刻仍停留在来源版本的记录条数
 * @param completed   该来源版本引用是否已清零
 */
public record TargetedMigrationProgress(
        int fromVersion,
        int toVersion,
        int total,
        int migrated,
        int skipped,
        int failed,
        int remaining,
        boolean completed
) {
}
