package com.github.lisama569.cryptokeylifecyclejava.migration;

import java.time.Instant;

/**
 * 迁移进度的可核验快照。checkpointId 为最后一个已处理记录的 id，
 * 中断后续跑从该 id 之后继续；剩余计数始终以全量扫描实时核验。
 */
public record MigrationProgress(String migrationId,
                                int fromVersion,
                                int toVersion,
                                String status,
                                long totalAtStart,
                                long migrated,
                                long skipped,
                                long failed,
                                long remainingByVersion,
                                String checkpointId,
                                Instant startedAt,
                                Instant finishedAt,
                                String lastIssue) {
}
