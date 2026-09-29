package com.github.lisama569.cryptokeylifecyclejava.error;

/**
 * 轮换在提交过程中失败（如写状态存储中断）。
 *
 * <p>与 {@link KeyConflictException} 区分：后者表示请求与当前状态冲突（语义拒绝），
 * 本异常表示轮换流程被基础设施故障打断；此时本次变更已在锁内回滚，
 * 轮换前的 ACTIVE 版本恢复可用，历史数据照常可解。
 */
public class RotationFailedException extends KeyLifecycleException {
    public RotationFailedException(String message) { super(message); }
    public RotationFailedException(String message, Throwable cause) { super(message, cause); }
    @Override public String reasonCode() { return "ROTATION_FAILED"; }
}
