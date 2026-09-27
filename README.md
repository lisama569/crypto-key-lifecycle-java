# 本地密钥生命周期管理（crypto-key-lifecycle-java）

一套完全运行在本地的密钥生命周期管理能力：密钥受**版本标识**管理，支持生成、启用、
轮换、吊销、历史数据迁移，以及**版本引用统计、安全下线预检与受保护下线、按来源版本
定向清理**；轮换期间加解密可并发执行，异常输入、并发冲突与数据篡改均有**可区分的失败
原因**，不返回错误明文、不留半更新状态。下线旧版本前可以先看清“还有多少数据依赖它”，
引用清零并确认它不再是服务版本后才允许停用，形成“看依赖 → 定向清理 → 释放旧版本”的闭环。

- 运行环境：Java 21+、Spring Boot 3.4、JUnit 5
- 外部依赖：**无**。仅依赖 JDK 密码学原语（AES/GCM）与 Spring/Web、测试框架；
  不访问网络、不使用真实凭据，存储为进程内内存实现。

---

## 1. 核心概念与密钥状态转换

每个密钥版本有五种状态：

| 状态 | 含义 | 加密 | 解密 |
|------|------|------|------|
| `PENDING` | 已生成密钥材料、尚未启用（轮换中间态，正常不可见地短暂存在） | 否 | 否 |
| `ACTIVE` | 当前唯一启用版本，**新产生的数据只允许使用它** | 是 | 是 |
| `RETIRED` | 轮换后进入保留期的旧版本，仅供解密历史数据；引用清零后可安全下线 | 否 | 是 |
| `REVOKED` | 终态。因密钥泄露/废弃而吊销，任何加解密一律拒绝 | 否 | 否 |
| `DECOMMISSIONED` | 终态。确认零引用、不再服务后**安全下线**的版本，仅保留审计元数据 | 否 | 否 |

状态转换图：

```text
                 generateAndActivate()/rotate()
   (不存在) ───────────────────────────────► ACTIVE
                                               │ rotate()
                                               ▼
                                            RETIRED ── revoke() ──┐
                                               │                  ▼
                                               │ decommission()  REVOKED
                                               │ (引用清零)        (终态)
                                               ▼
                                         DECOMMISSIONED
                                            (终态)
```

规则要点：

1. 任意时刻最多只有一个稳定的 `ACTIVE`；重复初始化（`generateAndActivate`）被拒绝
   （`KEY_STATE_CONFLICT`），同一版本不会被重复启用。轮换时按“新版本 PENDING→ACTIVE、
   **旧版本随后才 ACTIVE→RETIRED**”的顺序切换，因此切换过程中始终存在可服务的 ACTIVE，
   并发加密不会遇到“无 ACTIVE”窗口（期间可能瞬时存在两个 ACTIVE，加密取任一均为合法版本）。
2. `rotate()` 全程持有生命周期锁，并发轮换被**串行化**；中途异常会回滚（旧版本保持/恢复
   `ACTIVE`，未完成切换的新版本直接删除、版本号下次复用），不会留下半更新状态。
3. `REVOKED` 与 `DECOMMISSIONED` 都是终态、互不从属：重复吊销返回 `REVOKED_VERSION`；
   重复下线返回 `VERSION_DECOMMISSIONED`；吊销未知版本返回 `UNKNOWN_VERSION`，彼此可区分。
   下线只允许从 `RETIRED` 出发；对 `ACTIVE` 版本下线被 `VERSION_ACTIVE` 拒绝。

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
| `UNKNOWN_VERSION` | 信封版本号在密钥库中不存在、预检/下线/定向清理未知版本 | 404 |
| `REVOKED_VERSION` | 使用已吊销版本加密/解密、重复吊销、对已吊销版本下线 | 409 |
| `INTEGRITY_FAILURE` | GCM 标签校验失败（数据被篡改/密钥不匹配） | 409 |
| `KEY_STATE_CONFLICT` | 重复初始化、无 ACTIVE 时加密、对 PENDING/当前 ACTIVE 版本定向清理 | 409 |
| `VERSION_ACTIVE` | 对当前正在提供服务的 ACTIVE 版本执行安全下线 | 409 |
| `VERSION_STILL_REFERENCED` | 版本仍被历史数据引用（引用数未清零）时下线 | 409 |
| `VERSION_DECOMMISSIONED` | 重复下线已 DECOMMISSIONED 版本、或用其解密 | 409 |

异常输入不会导致服务不可用（拒绝后后续请求正常），错误响应形如
`{"error":"REVOKED_VERSION","message":"..."}`，**不含任何明文或密文片段**。

判定顺序：先解析信封（非法格式 → `INVALID_INPUT`）→ 查版本（未知 →
`UNKNOWN_VERSION`）→ 查状态（吊销 → `REVOKED_VERSION`）→ GCM 校验
（篡改 → `INTEGRITY_FAILURE`），因此三类拒绝原因互不混淆。

## 3. 轮换语义（服务持续运行）

- 轮换与在线加密/解密不互斥：加密始终读取当下唯一 `ACTIVE`，轮换后新数据只使用新版本；
- 轮换前产生的数据携带旧版本号，只要旧版本处于 `RETIRED` 保留期内，解密照常工作；
- 连续多次轮换后，整条 `RETIRED` 链上的历史数据在被吊销或安全下线前都可正确解密；
  一旦某代经引用清零后 `decommission` 成为 `DECOMMISSIONED`，它才彻底退出解密能力。

## 4. 吊销与历史数据迁移

推荐顺序：**先迁移，后吊销**。若是正常退役（而非密钥泄露），更推荐走第 5 节的
**先定向清理、确认引用清零、再安全下线（decommission）** 闭环；吊销是不需要等引用清零的
应急终态，二者语义不同、互不从属。

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

## 5. 版本引用统计、安全下线与定向清理

旧版本能否真正“拿掉”，取决于两件事：**还有多少数据以它加密（引用）**、以及**它是不是
当前正在提供服务的版本**。本层能力把这两件事变成可查询、可门禁、可收敛的闭环：

```text
看清依赖                定向清理                  满足门禁后释放
GET .../references  →  POST /migrate/version  →  POST /decommission
(引用数 + 预检结论)      (只清某一代, 可分批)       (RETIRED → DECOMMISSIONED)
```

### 5.1 引用统计与下线预检

`GET /api/keys/versions/{v}/references` 与 `POST /api/keys/decommission/preflight`
返回同一份 `VersionReferenceReport`：

| 字段 | 含义 |
|------|------|
| `version` / `state` | 被查询版本与其当前状态 |
| `references` | 此刻仍以该版本加密的数据条数（实时全量扫描） |
| `activeVersion` | 当前正在提供服务的版本号 |
| `canDecommission` | 是否满足安全下线条件：状态为 `RETIRED` 且引用清零且非服务版本 |
| `blockedReason` | 不能下线时的稳定原因码；可下线时为 `null` |
| `decommissionedAt` | 已下线时间戳；未下线为 `null` |

阻塞原因与门禁拒绝一一对应，**“被数据挡住”和“正在服务”可明确区分**：

| state / 条件 | blockedReason |
|--------------|---------------|
| `ACTIVE`（正在服务） | `CURRENTLY_ACTIVE` |
| `RETIRED` 且 `references > 0` | `STILL_REFERENCED` |
| `RETIRED` 且引用清零 | `null`（可下线） |
| `REVOKED` | `ALREADY_REVOKED` |
| `DECOMMISSIONED` | `ALREADY_DECOMMISSIONED` |
| `PENDING` | `NOT_RETIRED` |

一致性：统计在**共享维护锁**内完成“读版本状态 + 全量扫描引用计数”，与全量/定向迁移及
下线互斥。报告中的状态与引用数来自同一时刻，迁移每批结束（锁释放）后的下一次查询即可看到
引用数实时下降，因此不会出现“一边显示引用清零、一边仍有旧数据解不开”的自相矛盾结论。

### 5.2 受保护的安全下线

`POST /api/keys/decommission`，body `{"version":N}`。它在同一把维护锁内执行
“**再判定一次引用 → 状态机切换 `RETIRED→DECOMMISSIONED`**”：

- 版本不存在 → `UNKNOWN_VERSION`（404）；
- 是当前服务版本 → `VERSION_ACTIVE`（409）；
- 仍被数据引用 → `VERSION_STILL_REFERENCED`（409）；
- 已吊销 → `REVOKED_VERSION`（409）；
- 已经下线后重复提交 → `VERSION_DECOMMISSIONED`（409）。

只有“引用清零且不再是唯一在用版本”时才成功，且状态切换在生命周期锁内原子完成，
不存在部分成功或半停用。并发抢同一个版本时，请求被维护锁串行化，**最终恰好一个成功**，
其余全部得到一致的 `VERSION_DECOMMISSIONED` 冲突结果。下线成功后该版本密钥不再服务任何
加解密：残留的该版本密文再解密会得到可区分的 `VERSION_DECOMMISSIONED`（在库数据此时已
迁移到新版本，仍可正常解开）。

> 与吊销的语义边界：`revoke` 用于密钥泄露/废弃，是**立即拒绝**该版本一切加解密的终态；
> `decommission` 用于正常退役，是**确认零引用之后**的终态。两者互不从属，也不能互相转换。

### 5.3 按来源版本定向清理

`POST /api/keys/migrate/version?version=N&limit=100` 只把**指定旧版本 N** 的记录
“解旧密文 → 用当前 ACTIVE 重加密”，其他代旧版本完全不受影响，返回
`TargetedMigrationProgress{fromVersion,toVersion,total,migrated,skipped,failed,remaining,completed}`。

- **可分批 / 中断续跑**：每条独立 CAS 提交，处理到 `limit` 即返回；再次调用从该来源版本的
  剩余记录继续；不传 `limit` 用配置默认批量大小，传 `0` 表示一次性处理全部。
- **幂等**：候选仅按“密文版本 == 指定来源且 != 当前版本”判定；重复执行只跳过，不改写密文、
  不改变明文含义。
- **多代独立收敛**：连续轮换两次以上后（v1、v2 都旧、v3 在服务），可先 `version=1` 清掉
  第一代，确认其 `references` 归零并下线，再独立处理 `version=2`。
- **失败隔离**：来源版本已吊销等导致某条无法解密时计入 `failed` 并原样保留密文。
- 来源版本未知 → `UNKNOWN_VERSION`；来源就是当前 ACTIVE（没有可清理的历史数据）→
  `KEY_STATE_CONFLICT`。

### 5.4 清理与下线并发时的最终可见状态

定向清理与安全下线共用同一把维护锁，二者并发时只会出现两种结果，**绝不会出现“版本已
停用但历史数据打不开”**：

1. 下线请求到达时引用已清零 → 下线成功，库里没有任何记录指向该版本；
2. 引用尚未清零 → 下线被明确拒绝（`VERSION_STILL_REFERENCED`），版本保持 `RETIRED`、
   数据原样可解，清理继续推进，稍后重试即可成功。

## 6. REST 接口

| 方法与路径 | 说明 |
|------------|------|
| `POST /api/keys/encrypt` | body `{"plaintext":"..."}`，用当前 ACTIVE 加密 |
| `POST /api/keys/decrypt` | body `{"ciphertext":"v..:..."}`，按信封版本解密 |
| `POST /api/keys/rotate` | 原子轮换，返回 `{previousVersion, activeVersion}` |
| `POST /api/keys/revoke` | body `{"version":2}`，吊销指定版本 |
| `GET  /api/keys/versions` | 列出全部版本及状态/时间戳，供审计核验 |
| `POST /api/keys/migrate?limit=100` | 执行一批全量迁移；不传 limit 用配置默认值，传 `0` 表示全量 |
| `GET  /api/keys/migrate/progress` | 实时全量迁移进度 |
| `POST /api/keys/migrate/version?version=1&limit=100` | 按来源版本定向清理一批，只处理该版本记录 |
| `GET  /api/keys/versions/{v}/references` | 该版本实时引用数 + 安全下线预检结论 |
| `POST /api/keys/decommission/preflight` | body `{"version":1}`，只预检、不改状态 |
| `POST /api/keys/decommission` | body `{"version":1}`，满足门禁才安全下线 |

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

# 旧版本安全下线闭环：先看引用，再下线
curl -s localhost:8080/api/keys/versions/1/references
# {"version":1,"state":"RETIRED","references":0,"activeVersion":2,"canDecommission":true,...}
curl -s -XPOST localhost:8080/api/keys/decommission -H 'Content-Type: application/json' \
  -d '{"version":1}'
# {"version":1,"state":"DECOMMISSIONED",...}

# 仍在提供服务的版本会被明确挡住
curl -s -XPOST localhost:8080/api/keys/decommission -H 'Content-Type: application/json' \
  -d '{"version":2}'
# {"error":"VERSION_ACTIVE","message":"...the active serving version..."}
```

多代旧版本逐代清理的典型顺序：

```bash
# 假设已经轮换到 v3：v1、v2 为 RETIRED
curl -s -XPOST 'localhost:8080/api/keys/migrate/version?version=1&limit=200'
curl -s -XPOST localhost:8080/api/keys/decommission -H 'Content-Type: application/json' -d '{"version":1}'
curl -s -XPOST 'localhost:8080/api/keys/migrate/version?version=2&limit=200'
curl -s -XPOST localhost:8080/api/keys/decommission -H 'Content-Type: application/json' -d '{"version":2}'
```

## 7. 迁移的验证方法（测试如何核验）

`MigrationServiceTest` 覆盖了可核验的完整路径：

1. 准备 10 条 v1 数据后轮换到 v2；
2. 分批 `migrate(4)`、`migrate(4)`、`migrate(4)`，断言每批 `migrated/remaining/percent`，
   验证**中断续跑**（40% → 80% → 100%）；
3. 再连续执行两轮全量迁移，断言 `migrated=0, skipped=全部`、密文字节不再变化，
   验证**幂等**；并断言每条记录明文仍与最初一致（明文含义不变）且只有单一一致状态；
4. 先吊销 v1 再迁移，断言 `failed>0`、`completed=false`、失败记录密文原样保留；
5. 迁移途中再次轮换，断言续跑自动指向最新版本并最终全部收敛。

新增能力的验证分散在以下用例（数据量均到百/千条级）：

- `VersionReferenceServiceTest`：多版本（v1 1200 条 / v2 无引用 / v3 500 条）的实时引用计数、
  `CURRENTLY_ACTIVE` 与 `STILL_REFERENCED` 阻塞原因区分、千条数据分批定向清理过程中引用数
  逐批下降且**与实际在库数据始终一致**、引用清零后历史数据全部仍可解；
- `VersionDecommissionServiceTest`：清理→引用归零→下线的完整闭环；仍被引用 / 服务中 /
  不存在 / 已吊销 / 重复下线分别得到可区分原因；下线后残留旧密文被 `VERSION_DECOMMISSIONED`
  拒绝、在库新密文正常；
- `TargetedCleanupTest`：千条数据分批 `300+300+300+100` 中断续跑、重复清理幂等不改密文与
  明文、两次轮换后 v1 与 v2 两代各自独立收敛、来源为 ACTIVE/未知版本被拒、来源吊销时失败
  保留原密文；
- `DecommissionConcurrencyTest`：**并发竞争场景**——8 线程并发下线同一无引用版本，恰好一个
  成功、其余全部得到一致的 `VERSION_DECOMMISSIONED`；1000 条数据上定向清理与下线持续并发，
  成功前拒绝原因只能是 `VERSION_STILL_REFERENCED`，最终版本为 `DECOMMISSIONED` 且库里零残留；
- `DecommissionWebApiTest`：新端点在 HTTP 层的 200/400/404/409 与原因码区分。

## 8. 关键配置项（`application.properties`）

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| `keylifecycle.aes-key-bits` | `256` | AES 密钥位宽，仅允许 128/192/256 |
| `keylifecycle.gcm-iv-bytes` | `12` | GCM 随机 IV 长度（字节） |
| `keylifecycle.gcm-tag-bits` | `128` | GCM 认证标签长度（位） |
| `keylifecycle.migration-batch-size` | `100` | `/migrate` 与 `/migrate/version` 未显式传 `limit` 时的默认批量大小 |
| `logging.level...cryptokeylifecyclejava` | `INFO` | 打印密钥版本、操作类型与判定依据 |

## 9. 测试与日志

```bash
mvn test            # 全离线运行，共 45 个用例
```

覆盖场景：AES/GCM 往返与随机 IV、密文篡改/IV 篡改/错误密钥、信封畸形输入、
密钥状态机（含 `DECOMMISSIONED` 终态）、**并发轮换**（16 线程串行化、唯一 ACTIVE、无重复版本）、
**轮换与加解密并发**（多阶段屏障下约 1600 条消息全部可解、版本均合法、零加密失败）、
**全量迁移中断续跑/幂等/跨轮换续跑/吊销源版本失败隔离**、**并发迁移收敛**、
**版本引用统计与预检**、**安全下线门禁（含 8 线程并发竞争唯一成功）**、
**千条定向清理的中断续跑/幂等/多代独立收敛**、**清理与下线并发不产生孤儿数据**、
数据篡改端到端拒绝，以及 REST 层状态码与原因码的区分。

单测与组件日志统一输出三要素，便于审计（能看出密钥版本、操作类型与判定依据）：

```text
version=<密钥版本> op=<ENCRYPT|DECRYPT|ROTATE|REVOKE|MIGRATE|TARGETED_CLEANUP|
                         INSPECT_REFERENCES|DECOMMISSION>
basis=<判定依据，如 GCM_TAG_MISMATCH / ATOMIC_SWITCH / RETIRED_IN_RETENTION /
                  STILL_REFERENCED / CURRENTLY_ACTIVE / REFERENCES_CLEARED / GATE_PASSED>
result=<ACCEPT|REJECT|DONE|...>，失败时带 reason=<原因码>
```

## 10. 代码结构

```text
crypto/       AesGcmCipher(加解密原语) CipherCodec(信封编解码)
              KeyVersion/KeyState(版本与状态，含 DECOMMISSIONED)
              KeyStore/InMemoryKeyStore(线程安全存储) KeyManager(状态机/原子轮换/加解密/下线)
migration/    DataRecord/RecordStatus DataRepository(含 CAS 提交)
              MigrationService(全量迁移 + 按来源版本定向清理)
              MigrationProgress/TargetedMigrationProgress
decommission/ MaintenanceLock(迁移与下线共享维护锁) VersionReferenceService(引用统计+预检)
              VersionDecommissionService(安全下线门禁+执行) VersionReferenceReport
error/        可区分异常（UNKNOWN_VERSION / REVOKED_VERSION / INTEGRITY_FAILURE /
              INVALID_INPUT / KEY_STATE_CONFLICT / VERSION_ACTIVE /
              VERSION_STILL_REFERENCED / VERSION_DECOMMISSIONED）
config/       KeyLifecycleProperties + Spring 本地装配（启动自动启用 v1）
web/          REST 控制器与统一异常处理（原因码 → HTTP 状态码，错误体无明文）
```
