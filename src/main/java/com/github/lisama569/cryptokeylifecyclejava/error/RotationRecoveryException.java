package com.github.lisama569.cryptokeylifecyclejava.error;

/**
 * 轮换失败后的回滚（恢复）本身又失败，或回滚后状态不满足“仍有一个在用版本”不变式。
 *
 * <p>与普通的 {@link KeyConflictException}（轮换失败但已干净回滚）可区分：
 * 本异常意味着系统可能处于需要人工介入的危险状态，映射为 5xx。
 */
public class RotationRecoveryException extends KeyLifecycleException {
    public RotationRecoveryException(String message) { super(message); }
    public RotationRecoveryException(String message, Throwable cause) { super(message, cause); }
    @Override public String reasonCode() { return "ROTATION_RECOVERY_FAILED"; }
}
