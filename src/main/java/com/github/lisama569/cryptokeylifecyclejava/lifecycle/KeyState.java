package com.github.lisama569.cryptokeylifecyclejava.lifecycle;

/**
 * 密钥版本状态。
 *
 * <pre>
 * CREATED ──enable──▶ ENABLED ──(新版本启用)──▶ RETIRED ──revoke(无引用)──▶ REVOKED
 *                          └────────────────revoke(无引用)──────────────────▶ REVOKED
 * </pre>
 *
 * <ul>
 *   <li>CREATED: 已生成但尚未启用，不可用于加解密</li>
 *   <li>ENABLED: 当前启用版本，新加密只允许使用该版本</li>
 *   <li>RETIRED: 被轮换下线，版本保留期内仍可解密历史数据，不可新加密</li>
 *   <li>REVOKED: 终态，任何加解密/迁移操作都被拒绝</li>
 * </ul>
 */
public enum KeyState {
    CREATED,
    ENABLED,
    RETIRED,
    REVOKED
}
