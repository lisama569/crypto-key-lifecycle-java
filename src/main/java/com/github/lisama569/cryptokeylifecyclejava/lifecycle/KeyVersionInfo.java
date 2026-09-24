package com.github.lisama569.cryptokeylifecyclejava.lifecycle;

import java.time.Instant;

/** 对外暴露的版本视图（不含密钥材料）。 */
public record KeyVersionInfo(int version, KeyState state, Instant createdAt, boolean current) {
}
