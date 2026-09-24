package com.github.lisama569.cryptokeylifecyclejava.error;

/**
 * 可区分的失败原因枚举。所有被拒绝的操作都必须携带其中一个原因，
 * 便于调用方与测试断言区分“未知版本 / 已吊销 / 完整性失败”等情形。
 */
public enum FailureReason {
    /** 引用的密钥版本不存在 */
    UNKNOWN_VERSION,
    /** 引用的密钥版本已被吊销 */
    REVOKED_VERSION,
    /** 密钥版本当前状态不允许该状态转换（例如重复启用同一版本） */
    INVALID_VERSION_STATE,
    /** 密文被篡改或认证标签校验失败 */
    INTEGRITY_FAILURE,
    /** 已有轮换在进行中，并发触发被快速拒绝 */
    CONCURRENT_ROTATION,
    /** 输入非法（null、空明文、超长、密文格式错误等） */
    INVALID_INPUT,
    /** 待吊销版本仍被历史数据引用，拒绝吊销 */
    REFERENCES_REMAIN,
    /** 迁移源/目标版本状态不满足迁移前置条件 */
    MIGRATION_NOT_RUNNABLE,
    /** 迁移过程中同一条记录被并发改写，产生冲突 */
    MIGRATION_CONFLICT
}
