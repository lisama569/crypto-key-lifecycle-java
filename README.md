# 本地密钥生命周期管理（crypto-key-lifecycle-java）

一套完全运行在本地的密钥生命周期管理能力：密钥受**版本标识**管理，支持生成、启用、
轮换、吊销以及历史数据迁移；轮换期间加解密可并发执行，异常输入、并发冲突与数据篡改
均有**可区分的失败原因**，不返回错误明文、不留半更新状态。

- 运行环境：Java 21+、Spring Boot 3.4、JUnit 5
- 外部依赖：**无**。仅依赖 JDK 密码学原语（AES/GCM）与 Spring/Web、测试框架；
  不访问网络、不使用真实凭据，存储为进程内内存实现。

---

## 1. 核心概念与密钥状态转换

每个密钥版本有四种状态：

| 状态 | 含义 | 加密 | 解密 |
|------|------|------|------|
| `PENDING` | 已生成密钥材料、尚未启用（轮换中间态，正常不可见地短暂存在） | 否 | 否 |
| `ACTIVE` | 当前唯一启用版本，**新产生的数据只允许使用它** | 是 | 是 |
| `RETIRED` | 轮换后进入保留期的旧版本，仅供解密历史数据 | 否 | 是 |
| `REVOKED` | 终态。任何加解密一律拒绝 | 否 | 否 |

状态转换图：

```text
                 generateAndActivate()/rotate()
   (不存在) ───────────────────────────────► ACTIVE
                                               │ rotate()
                                               ▼
                                            RETIRED ── revoke() ──┐
                                               │                  ▼
                          revoke() ────────────┴──────────────► REVOKED
                                                                 (终态)
```

规则要点：

1. 任意时刻最多只有一个 `ACTIVE`；重复初始化（`generateAndActivate`）被拒绝
   （`KEY_STATE_CONFLICT`），同一版本不会被重复启用。
2. `rotate()` 原子完成三步：写入新版本 `PENDING` → 旧 `ACTIVE` 转 `RETIRED`
   → 新版本转 `ACTIVE`。全程持有生命周期锁，并发轮换被**串行化**；中途异常会回滚
   （旧版本恢复 `ACTIVE`，未启用的新版本标记 `REVOKED` 作为废版本审计痕迹），
   不会留下半更新状态。
3. `REVOKED` 是终态：重复吊销返回 `REVOKED_VERSION`；吊销未知版本返回
   `UNKNOWN_VERSION`，两者可区分。

## 2. 密文格式与失败原因

密文为自描述信封（`CipherCodec`）：

```text
v<密钥版本号>:<base64url(IV)>:<base64url(GCM 密文+认证标签)>
```

- 每次加密使用随机 IV（默认 12 字节），同一明文两次密文不同；
- AES-256/GCM，128 bit 认证标签；篡改密文、IV 或使用错误密钥均导致标签校验失败。

所有失败都继承 `KeyLifecycleException`，携带稳定的机器可读原因码：

| reasonCode | 触发场景 | HTTP 状态码 |
|------------|----------|-------------|
| `INVALID_INPUT` | null/空明文、空入参、密文信封格式非法、请求体损坏 | 400 |
| `UNKNOWN_VERSION` | 信封版本号在密钥库中不存在 | 404 |
| `REVOKED_VERSION` | 使用已吊销版本加密/解密、重复吊销 | 409 |
| `INTEGRITY_FAILURE` | GCM 标签校验失败（数据被篡改/密钥不匹配） | 409 |
| `KEY_STATE_CONFLICT` | 重复初始化、无 ACTIVE 时加密、并发状态冲突 | 409 |

异常输入不会导致服务不可用（拒绝后后续请求正常），错误响应形如
`{"error":"REVOKED_VERSION","message":"..."}`，**不含任何明文或密文片段**。

判定顺序：先解析信封（非法格式 → `INVALID_INPUT`）→ 查版本（未知 →
`UNKNOWN_VERSION`）→ 查状态（吊销 → `REVOKED_VERSION`）→ GCM 校验
（篡改 → `INTEGRITY_FAILURE`），因此三类拒绝原因互不混淆。

## 3. 轮换语义（服务持续运行）

- 轮换与在线加密/解密不互斥：加密始终读取当下唯一 `ACTIVE`，轮换后新数据只使用新版本；
- 轮换前产生的数据携带旧版本号，只要旧版本处于 `RETIRED` 保留期内，解密照常工作；
- 连续多次轮换后，整条 `RETIRED` 链上的历史数据在被吊销前都可正确解密。

## 4. 吊销与历史数据迁移

推荐顺序：**先迁移，后吊销**。

迁移服务 `MigrationService` 把旧版本密文“解旧密文 → 用当前 `ACTIVE` 重新加密”，
保证语义：

- **幂等**：候选记录仅按“密文版本 ≠ 当前版本”判定。已是当前版本的记录跳过；
  重复迁移不改写密文、不改变明文含义；提交使用记录级 CAS
  （`compareAndUpdateStatus`），并发迁移同一条记录不会产生互相冲突的状态。
- **可中断续跑**：`migrate(limit)` 每批处理 `limit` 条后返回；再次调用从剩余旧版本
  记录继续，不必从头开始。
- **进度可核验**：每批与 `GET /api/keys/migrate/progress` 均返回
  `MigrationProgress`：`fromVersion/toVersion/total/migrated/skipped/failed/remaining/completed/percent()`，
  其中 `completed` 由实时扫描得出。
- **失败隔离**：源版本已吊销等导致某条记录无法解密时，该条计入 `failed` 并**原样
  保留密文**，其余记录继续迁移，数据不被破坏。
- 迁移期间再次轮换也是安全的：续跑批次自动以最新的当前版本为目标，最终全部收敛。

数据记录状态（`RecordStatus`）：`CURRENT`（密文已在当前版本或迁移完成）。
迁移不引入会长期残留的中间状态：每条记录的“解密—重加密—CAS 提交”独立完成。

## 5. REST 接口

| 方法与路径 | 说明 |
|------------|------|
| `POST /api/keys/encrypt` | body `{"plaintext":"..."}`，用当前 ACTIVE 加密 |
| `POST /api/keys/decrypt` | body `{"ciphertext":"v..:..."}`，按信封版本解密 |
| `POST /api/keys/rotate` | 原子轮换，返回 `{previousVersion, activeVersion}` |
| `POST /api/keys/revoke` | body `{"version":2}`，吊销指定版本 |
| `GET  /api/keys/versions` | 列出全部版本及状态/时间戳，供审计核验 |
| `POST /api/keys/migrate?limit=100` | 执行一批迁移；不传 limit 用配置默认值，传 `0` 表示全量 |
| `GET  /api/keys/migrate/progress` | 实时迁移进度 |

启动时自动生成并启用首个密钥版本（`v1`），因此开箱即可加解密。

### 手工验证（本地）

```bash
mvn spring-boot:run

curl -s -XPOST localhost:8080/api/keys/encrypt -H 'Content-Type: application/json' \
  -d '{"plaintext":"hello-密钥"}'
# {"ciphertext":"v1:...","keyVersion":1}

curl -s -XPOST localhost:8080/api/keys/rotate
# {"previousVersion":1,"activeVersion":2}

curl -s -XPOST localhost:8080/api/keys/migrate
# {"fromVersion":1,"toVersion":2,...,"completed":true,...}

curl -s -XPOST localhost:8080/api/keys/revoke -H 'Content-Type: application/json' \
  -d '{"version":1}'
# {"version":1,"state":"REVOKED",...}
```

## 6. 迁移的验证方法（测试如何核验）

`MigrationServiceTest` 覆盖了可核验的完整路径：

1. 准备 10 条 v1 数据后轮换到 v2；
2. 分批 `migrate(4)`、`migrate(4)`、`migrate(4)`，断言每批 `migrated/remaining/percent`，
   验证**中断续跑**（40% → 80% → 100%）；
3. 再连续执行两轮全量迁移，断言 `migrated=0, skipped=全部`、密文字节不再变化，
   验证**幂等**；并断言每条记录明文仍与最初一致（明文含义不变）且只有单一一致状态；
4. 先吊销 v1 再迁移，断言 `failed>0`、`completed=false`、失败记录密文原样保留；
5. 迁移途中再次轮换，断言续跑自动指向最新版本并最终全部收敛。

## 7. 关键配置项（`application.properties`）

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| `keylifecycle.aes-key-bits` | `256` | AES 密钥位宽，仅允许 128/192/256 |
| `keylifecycle.gcm-iv-bytes` | `12` | GCM 随机 IV 长度（字节） |
| `keylifecycle.gcm-tag-bits` | `128` | GCM 认证标签长度（位） |
| `keylifecycle.migration-batch-size` | `100` | `/migrate` 未显式传 `limit` 时的默认批量大小 |
| `logging.level...cryptokeylifecyclejava` | `INFO` | 打印密钥版本、操作类型与判定依据 |

## 8. 测试与日志

```bash
mvn test            # 全离线运行，共 29 个用例
```

覆盖场景：AES/GCM 往返与随机 IV、密文篡改/IV 篡改/错误密钥、信封畸形输入、
密钥状态机、**并发轮换**（16 线程串行化、唯一 ACTIVE、无重复版本）、
**轮换与加解密并发**（约 1600 条消息全部可解、版本均合法）、**迁移中断续跑/幂等/
跨轮换续跑/吊销源版本失败隔离**、**并发迁移收敛**、数据篡改端到端拒绝、
以及 REST 层状态码与原因码的区分。

单测与组件日志统一输出三要素，便于审计：

```text
version=<密钥版本> op=<ENCRYPT|DECRYPT|ROTATE|REVOKE|MIGRATE|...>
basis=<判定依据，如 GCM_TAG_MISMATCH / ATOMIC_SWITCH / RETIRED_IN_RETENTION>
result=<PASS|REJECTED|...>，失败时带 reason=<原因码>
```

## 9. 代码结构

```text
crypto/    AesGcmCipher(加解密原语) CipherCodec(信封编解码)
           KeyVersion/KeyState(版本与状态) KeyStore/InMemoryKeyStore(线程安全存储)
           KeyManager(生命周期门面：状态机/原子轮换/加解密判定)
migration/ DataRecord/RecordStatus DataRepository(含 CAS 提交)
           MigrationService(幂等/可中断/可核验迁移) MigrationProgress
error/     五类可区分异常（UNKNOWN_VERSION / REVOKED_VERSION /
           INTEGRITY_FAILURE / INVALID_INPUT / KEY_STATE_CONFLICT）
config/    KeyLifecycleProperties + Spring 本地装配（启动自动启用 v1）
web/       REST 控制器与统一异常处理（原因码 → HTTP 状态码，错误体无明文）
```
