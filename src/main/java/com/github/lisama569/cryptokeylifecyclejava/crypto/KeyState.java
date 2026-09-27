package com.github.lisama569.cryptokeylifecyclejava.crypto;

/** 密钥版本的生命周期状态。 */
public enum KeyState {
    /** 已生成但尚未启用，不能用于加解密。 */
    PENDING,
    /** 当前启用版本，新加密只允许使用该版本。 */
    ACTIVE,
    /** 已轮换、处于保留期内，仅允许解密历史数据。 */
    RETIRED,
    /** 已吊销，任何加解密操作一律拒绝。 */
    REVOKED,
    /** 已安全下线：引用清零且不再提供服务后的终态，仅保留审计元数据，拒绝任何加解密。 */
    DECOMMISSIONED
}
