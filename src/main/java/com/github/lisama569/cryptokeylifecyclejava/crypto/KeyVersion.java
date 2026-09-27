package com.github.lisama569.cryptokeylifecyclejava.crypto;

import java.time.Instant;

/** 一个受版本标识管理的密钥版本（含密钥材料与状态元数据）。 */
public record KeyVersion(
        int version,
        KeyState state,
        Instant createdAt,
        Instant retiredAt,
        Instant revokedAt,
        Instant decommissionedAt
) {
}
