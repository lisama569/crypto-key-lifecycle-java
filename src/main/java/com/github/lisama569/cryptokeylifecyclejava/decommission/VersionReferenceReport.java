package com.github.lisama569.cryptokeylifecyclejava.decommission;

/**
 * 单个密钥版本的引用统计与安全下线预检结论（实时扫描得出）。
 *
 * @param version       被查询的密钥版本
 * @param state         查询时刻该版本的生命周期状态
 * @param references    当前仍以该版本加密的数据条数
 * @param activeVersion 当前正在提供服务的版本号
 * @param canDecommission 是否满足安全下线条件（RETIRED 且引用清零且非服务版本）
 * @param blockedReason 不可下线时的稳定原因码；可下线时为 null
 * @param decommissionedAt 已下线时间戳（ISO-8601 字符串），未下线为 null
 */
public record VersionReferenceReport(
        int version,
        String state,
        long references,
        int activeVersion,
        boolean canDecommission,
        String blockedReason,
        String decommissionedAt
) {
}
