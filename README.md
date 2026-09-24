# 本地密钥生命周期管理（crypto-key-lifecycle-java）

一个只依赖本地运行环境（Spring Boot + JDK 加密原语 + 内存存储，无外部服务、无真实凭据、无网络资源）的
**版本化密钥生命周期管理**示例，覆盖：

- 受版本标识管理的密钥 **生成 / 启用 / 轮换 / 吊销**；
- 轮换期间加解密请求并发执行，新数据只写当前启用版本，旧数据在版本保留期内继续可解；
- 吊销前将历史数据 **幂等、可中断续跑、进度可核验** 地迁移到新版本；
- 对未知版本、已吊销版本、数据完整性失败给出**可区分的失败原因**，异常输入不返回错误明文、不影响服务可用性。

## 1. 密钥状态转换

每个密钥版本有四种状态（`KeyState`）：

```
CREATED ──enable──▶ ENABLED ──(新版本被启用/轮换)──▶ RETIRED ──revoke(引用清零)──▶ REVOKED
   ▲                    └──────────── revoke(引用清零) ────────────────────────▶ REVOKED
   │                                                                              │
 generateKey                                                                    终态
```

| 状态 | 语义 | 新加密 | 解密历史数据 |
| --- | --- | --- | --- |
| `CREATED` | 已生成，尚未启用 | 否 | 否（拒绝，`INVALID_VERSION_STATE`） |
| `ENABLED` | 当前启用版本（全局唯一） | 是，**只允许**该版本 | 是 |
| `RETIRED` | 被轮换下线，处于**版本保留期** | 否 | 是 |
| `REVOKED` | 终态，吊销 | 否 | 否（拒绝，`REVOKED_VERSION`） |

转换规则（`KeyLifecycleManager`）：

- `enableVersion(v)`：仅 `CREATED → ENABLED`；原 `ENABLED` 版本同时转为 `RETIRED`。
  重复启用当前版本、复用 `RETIRED` 版本一律拒绝（`INVALID_VERSION_STATE`），
  即**不会重复启用同一版本**。
- `rotate()`：原子地“生成新版本 + 启用 + 旧版本转 RETIRED”。
  并发触发时只有一个调用成功，其余快速失败为 `CONCURRENT_ROTATION`（HTTP 409），
  状态转换在同一把写锁内完成，**不存在“无当前版本/半更新”中间态**。
- `revokeVersion(v)`：
  - 未知版本 → `UNKNOWN_VERSION`（HTTP 404）；
  - 已吊销 → `REVOKED_VERSION`；
  - 当前 `ENABLED` 版本不允许直接吊销，必须先轮换 → `INVALID_VERSION_STATE`；
  - `RETIRED` 版本仍被数据引用 → `REFERENCES_REMAIN`（HTTP 409），
    必须先完成历史数据迁移、引用计数归零后才能吊销。

## 2. 并发语义

`KeyLifecycleManager` 使用一把公平 `ReentrantReadWriteLock`：

- 加解密路径在**读锁临界区内**完成“定位密钥版本 + AEAD 运算”，
  与轮换（写锁）线性一致：轮换进行中的加密请求要么全部落在旧版本、要么全部落在新版本，
  绝不会用“已被轮换一半”的状态写数据；
- 轮换 / 启用 / 吊销持有写锁，期间不会有任何加解密穿插观察中间态；
- 另有 `rotationGuard`（CAS）保证并发轮换只有一个成功。

## 3. 加密与完整性

- 算法：`AES_256/GCM/NoPadding`，每次加密生成随机 12 字节 IV，128 bit 认证标签；
- 密文为自描述线路编码：`v1:<keyVersion> <base64url(iv)>.<base64url(ciphertext||tag)>`；
- **密钥版本号同时作为 GCM 的 AAD** 参与认证：篡改版本头同样失败；
- 失败严格分两类，原因可区分：
  - 密文格式问题（截断、坏 Base64、长度错误等）→ `INVALID_INPUT`；
  - 格式合法但标签校验失败（密文/IV/AAD 被篡改、密钥不匹配）→ `INTEGRITY_FAILURE`，
    此时**绝不返回任何明文**。
- 所有异常文案只含版本号与原因，不含明文或密钥材料；`KeyVersion.toString()` 也不打印密钥。

## 4. 历史数据迁移

入口：`HistoricalDataMigrator.migrate(fromVersion, batchSize, maxBatches, migrationId)`。

前置条件：源版本必须是 `RETIRED`（保留期内可解密），且目标版本是与之不同的当前
`ENABLED` 版本，否则以 `MIGRATION_NOT_RUNNABLE` 拒绝。

### 4.1 幂等

- 每条记录处理前先检查版本：**只有仍引用源版本的记录才迁**，已在目标版本的记录计入 `skipped`；
- 单条记录流程为「读快照 → 源版本解密 → 目标版本加密 → **CAS 替换**」，
  CAS 以 `(keyVersion, cipherText)` 快照比对，失败则原密文原样保留；
- 因此：重复迁移（同一 `migrationId` 重跑，或新建迁移再跑）不会重复加密、
  不会改变明文含义，也不会让同一份数据出现互相冲突的版本状态。

### 4.2 可中断续跑

- 扫描按记录 id 字典序进行，**每处理完一条就推进 `checkpointId`**，中断最多损失当前一条工作量；
- `maxBatches × batchSize` 限定单次调用处理上限，到达后状态置 `PAUSED` 并返回 `migrationId`；
- 也可调用 `POST /api/migrations/{id}/interrupt` 请求中断，循环在下一条记录前安全暂停；
- 续跑时传入同一 `migrationId` 即从断点继续；此外每次续跑都会对 checkpoint 之前的记录做
  **滞留重扫**（处理上一轮 CAS 冲突未修复的记录），保证引用数最终可以收敛到零。

### 4.3 进度可核验

`MigrationProgress` 字段：

| 字段 | 含义 |
| --- | --- |
| `status` | `RUNNING / PAUSED / COMPLETED / FAILED` |
| `migrated` / `skipped` / `failed` | 跨续跑累计的迁移 / 跳过 / 失败条数 |
| `remainingByVersion` | **全表实时计数**仍引用源版本的记录数，与 migrated 独立，可交叉验证 |
| `checkpointId` | 最后已处理记录 id |
| `lastIssue` | 最近一次失败/冲突描述（如 CAS conflict、认证失败） |

完成判据：本轮扫描耗尽且 `remainingByVersion == 0` 且无失败 → `COMPLETED`；
有冲突/解密失败 → `FAILED`（已迁部分不回滚，修好冲突记录后重跑即可收敛）。

## 5. HTTP API

| 方法 & 路径 | 说明 |
| --- | --- |
| `POST /api/data/{id}` | body `{"plaintext":"..."}`，用当前版本加密并存储；响应只含 `id,keyVersion` |
| `GET  /api/data/{id}` | 解密读取，按密文自带版本路由密钥 |
| `POST /api/keys/rotate` | 原子轮换；并发失败者返回 `409 CONCURRENT_ROTATION` |
| `GET  /api/keys` | 列出版本、状态与当前指针（不含密钥材料） |
| `POST /api/keys/{v}/revoke` | 吊销；有引用 → `409 REFERENCES_REMAIN` |
| `POST /api/migrations` | body `{"fromVersion":1,"batchSize":50,"maxBatches":10,"migrationId":"mig-..."}`，后两项可省 |
| `GET  /api/migrations/{id}` | 查询迁移进度（实时剩余计数） |
| `POST /api/migrations/{id}/interrupt` | 请求安全中断 |

错误响应统一为 `{"reason":"...","message":"..."}`，`reason` 取值见
`FailureReason`：`UNKNOWN_VERSION / REVOKED_VERSION / INVALID_VERSION_STATE /
INTEGRITY_FAILURE / CONCURRENT_ROTATION / INVALID_INPUT / REFERENCES_REMAIN /
MIGRATION_NOT_RUNNABLE / MIGRATION_CONFLICT`。

## 6. 关键配置项（`application.properties`）

```properties
keylifecycle.key-size-bits=256            # AES 密钥位长度
keylifecycle.gcm-iv-length-bytes=12       # GCM IV 长度
keylifecycle.gcm-tag-length-bits=128      # GCM 认证标签长度
keylifecycle.migration-batch-size=100     # 迁移默认每批记录数
keylifecycle.bootstrap-key-on-startup=true# 启动自动生成并启用第一个版本
```

## 7. 如何运行与验证

```bash
mvn test          # 全部单测/集成测试（28 个，全部本地运行）
mvn spring-boot:run
```

测试覆盖（日志 logger：`KEY_LIFECYCLE_AUDIT` / 测试内 `KEY_LIFECYCLE_TEST`，
统一打印 `op=<操作类型> keyVersion=<版本> decision=<判定> reason='<判定依据>'`）：

- `AeadCipherServiceTest`：往返一致、随机 IV、密文/版本头篡改 → `INTEGRITY_FAILURE`、
  畸形输入 → `INVALID_INPUT`，两类原因断言区分；
- `KeyLifecycleManagerTest`：全部合法/非法状态转换、重复启用拒绝、未知/吊销版本区分；
- `CryptoRotationConcurrencyTest`：多线程加密 × 多轮轮换并发，全部密文可解、
  并发轮换只成功一次且失败原因唯一为 `CONCURRENT_ROTATION`；
- `MigrationIntegrationTest`：引用阻止吊销、分批 `PAUSED` + checkpoint 续跑、
  完成后吊销、重复迁移幂等且明文含义不变；
- `MigrationResilienceTest`：中断续跑、确定性 CAS 冲突（测试钩子注入并发改写）、
  存储密文直接篡改（1 条失败、其余照常迁移）、吊销后 `REVOKED_VERSION` 拒绝、非法迁移请求；
- `KeyLifecycleControllerTest`：完整 HTTP 生命周期、并发轮换 HTTP 状态码、
  缺字段/坏 JSON/未知资源全部映射为 4xx 且错误体不含明文。

> 说明：本实现使用内存存储，重启后密钥与数据不保留；这是刻意限定的本地演示边界，
> 接口与并发/迁移语义不依赖存储介质，可替换为持久化实现而不改变生命周期保证。
