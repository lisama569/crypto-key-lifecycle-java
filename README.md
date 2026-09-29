# 本地密钥生命周期管理（crypto-key-lifecycle-java）

一套完全运行在本地的密钥生命周期管理能力：密钥受**版本标识**管理，支持生成、启用、
轮换、吊销以及历史数据迁移；在此之上提供**版本引用统计、按来源版本定向清理与
受门禁保护的安全下线**，让旧版本的下线从人工判断变成可核验的闭环。轮换期间加解密
可并发执行，异常输入、并发冲突与数据篡改均有**可区分的失败原因**，不返回错误明文、
不留半更新状态。

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
2. `rotate()` 在存储的**同一次原子更新**内完成切换：先写入新版本 `PENDING` 种子，
   再在同一个存储临界区内完成“旧 `ACTIVE` → `RETIRED` 与新版本 → `ACTIVE`”。
   并发轮换被生命周期锁**串行化**；并发加密不取生命周期锁，但与切换共用存储
   monitor，只能观察到“切换前（旧版本 ACTIVE）”或“切换后（新版本 ACTIVE）”，
   **不存在“没有可用密钥版本”的窗口**。切换提交中途若存储失败，存储层在释放锁前
   自愈（旧版本恢复 `ACTIVE`），门面再移除未启用的 `PENDING` 种子，版本号可复用；
   不会留下半更新状态（详见第 3 节）。
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
| `UNKNOWN_VERSION` | 信封版本号在密钥库中不存在；统计/下线/定向清理未知版本 | 404 |
| `REVOKED_VERSION` | 使用已吊销版本加密/解密、重复吊销、重复/并发落败的安全下线 | 409 |
| `INTEGRITY_FAILURE` | GCM 标签校验失败（数据被篡改/密钥不匹配） | 409 |
| `KEY_STATE_CONFLICT` | 重复初始化、无 ACTIVE 时加密、并发状态冲突、清理当前 ACTIVE 版本 | 409 |
| `ROTATION_FAILED` | 轮换在原子切换提交阶段被存储故障打断（已在锁内回滚，旧 ACTIVE 恢复可用，历史数据仍可解） | 500 |
| `VERSION_STILL_REFERENCED` | 安全下线时版本仍被数据记录引用 | 409 |
| `VERSION_IS_ACTIVE` | 安全下线当前正在提供服务的 ACTIVE 版本 | 409 |

异常输入不会导致服务不可用（拒绝后后续请求正常），错误响应形如
`{"error":"REVOKED_VERSION","message":"..."}`，**不含任何明文或密文片段**。

判定顺序：先解析信封（非法格式 → `INVALID_INPUT`）→ 查版本（未知 →
`UNKNOWN_VERSION`）→ 查状态（吊销 → `REVOKED_VERSION`）→ GCM 校验
（篡改 → `INTEGRITY_FAILURE`），因此三类拒绝原因互不混淆。

## 3. 轮换语义（服务持续运行）

- **轮换与在线加密/解密真正不互斥**：轮换只持有生命周期锁串行化“轮换↔轮换”，
  加解密不取该锁。状态切换（旧 `ACTIVE→RETIRED`、新版本 `PENDING→ACTIVE`）在
  密钥存储的**同一个 monitor 临界区**内提交；加密侧的状态读取（`current()`）持
  同一把 monitor，因此它只能看到切换前或切换后的完整状态——**轮换的那一瞬间
  系统里也始终有且仅有一个可用于加密的版本，写入绝不会因为轮换报
  “no active key version available”**。
- 顺序保证：切换临界区内先退休旧版本、再启用新版本；若启用写入失败，存储在释放
  monitor 前把旧版本 Entry 原样写回（存储层自愈），随后门面对“从未启用”的
  `PENDING` 种子做清理。回滚完成后：恰好一个 `ACTIVE`（轮换前的旧版本）、
  无 `PENDING`/双 `ACTIVE` 残留、失败原因以 `ROTATION_FAILED` 与普通的
  `KEY_STATE_CONFLICT` 相区分，版本号可被下一次轮换复用。
- 轮换结束后新数据只使用新版本；轮换前产生的数据携带旧版本号，只要旧版本处于
  `RETIRED` 保留期内，解密照常工作。
- 连续多次轮换后，整条 `RETIRED` 链上的历史数据在被吊销前都可正确解密。

### 3.1 本地如何验证“轮换期间并发写入不失败”

自动化（确定性，不靠调度碰运气）：

```bash
mvn -Dtest=RotationCryptoConcurrencyTest test
# encryptionNeverFailsWhileRotationIsParkedInsideTheAtomicSwitch
#   轮换线程被测试栅栏精确挂在原子切换的两次状态写入之间（仍持有存储 monitor），
#   12 个加密线程共 600 次加密同时冲进 current()：修复后 0 失败，全部落在
#   切换后的 v2 并可正确解密，v1 历史数据照常解开；修复前该用例必现 600 次失败。
# failureInsideTheSwitchRollsBackWhileConcurrentEncryptionKeepsSucceeding
#   在同一挂起点注入存储故障：8 线程 400 次加密 0 失败；回滚后恰好一个 ACTIVE(v1)、
#   无半状态残留，历史与故障期间数据均由 v1 解开，故障解除后版本号 2 可复用，
#   失败原因码为 ROTATION_FAILED。
```

配套的非确定性压测与既有语义回归：

```bash
mvn -Dtest=KeyManagerConcurrencyTest test      # 4 轮“加密→轮换→加密”分阶段交错，
                                               # 1600 条消息 0 失败，版本 1..5 都被使用，
                                               # 看门狗全程采样“恰好一个 ACTIVE”
mvn test                                        # 全量 48 个用例，确认轮换/加解密/
                                               # 篡改拒绝/迁移/下线等均无回归
```

手工验证（两个终端持续压入写入，另一个终端轮换，写入侧不应出现失败）：

```bash
mvn spring-boot:run

# 终端 A：持续写入
while true; do
  curl -s -XPOST localhost:8080/api/keys/encrypt -H 'Content-Type: application/json' \
    -d '{"plaintext":"concurrent-write"}' | grep -q ciphertext || echo "ENCRYPT FAILED"
done

# 终端 B：连续轮换
for i in $(seq 1 10); do curl -s -XPOST localhost:8080/api/keys/rotate; echo; done
# 终端 A 全程不应打印 ENCRYPT FAILED；之后可用任意历史返回密文调 /decrypt 验证
```

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

## 5. 版本引用统计与安全下线

在轮换/吊销/迁移之上，`VersionLifecycleService` 提供“旧版本能否安全下线”的闭环：
**先看引用统计 → 定向清理 → 引用归零后安全下线**。

### 5.1 引用统计与下线预检

`GET /api/keys/versions/{v}/references`（单个）与 `GET /api/keys/references`（全量快照）
返回 `VersionReferenceStats`：

```json
{"version":1,"state":"RETIRED","referenceCount":6,"active":false,
 "safeToDecommission":false,"reason":"BLOCKED_BY_REFERENCES"}
```

- `referenceCount`：快照时刻仍引用该版本的数据记录条数，随迁移每批提交实时收敛；
- `reason` 预检结论可区分：`SAFE_TO_DECOMMISSION`（可下线）、
  `BLOCKED_BY_REFERENCES`（被数据引用挡住）、`BLOCKED_ACTIVE_VERSION`（当前在用版本）、
  `ALREADY_DECOMMISSIONED`（已是 REVOKED 终态）；
- 每次查询基于同一份数据快照计算，计数与结论不自相矛盾——显示引用清零时，
  仓库中确实不再存在该版本的记录。

### 5.2 受保护的安全下线（decommission）

`POST /api/keys/decommission` body `{"version":1}`：仅当**引用清零且该版本不是当前
ACTIVE** 时，版本才进入 `REVOKED` 终态。与 `revoke` 的区别：`revoke` 是无条件的运维
强制手段，`decommission` 是带门禁的安全下线，二者终态相同。

- 门禁判定（引用计数实时求值）与状态转换在生命周期锁内**原子完成**：
  并发抢同一版本时只有一个成功，其余得到一致的 `REVOKED_VERSION`；
  重复提交同样返回 `REVOKED_VERSION`；
- 拒绝原因可区分：未知版本 `UNKNOWN_VERSION`(404)、当前在用 `VERSION_IS_ACTIVE`(409)、
  仍被引用 `VERSION_STILL_REFERENCED`(409)；
- 拒绝是整体的：不改变版本状态、不影响加解密，不存在半停用状态。

### 5.3 按来源版本定向清理

`POST /api/keys/migrate/from/{fromVersion}?limit=100`：只处理仍停留在指定旧版本的
数据（全量 `POST /api/keys/migrate` 的语义子集），分批、中断续跑、幂等、失败隔离
语义与全量迁移一致；返回 `SourceCleanupProgress`
（`fromVersion/toVersion/sourceTotal/migrated/skipped/failed/remaining/completed/percent()`）。

- 多代旧版本并存时各代独立清理：清完某一代后其 `referenceCount` 精确归零，
  其他代记录一条不动；
- `fromVersion` 为当前 ACTIVE → `KEY_STATE_CONFLICT`；未知版本 → `UNKNOWN_VERSION`；
- 定向清理与安全下线并发时，下线门禁在锁内实时统计引用：清理未完成时下线被
  `VERSION_STILL_REFERENCED` 稳定拒绝，引用清零后下线才成功——**不会出现版本已停用
  但历史数据打不开的窗口**。

### 5.4 与原有语义的兼容范围

- 轮换、吊销、全量迁移、加解密行为完全不变；`decommission` 与 `revoke` 共用
  `REVOKED` 终态，解密判定不需要任何新规则；
- 被安全下线的版本与未下线的 `RETIRED` 版本在统计中可区分
  （`ALREADY_DECOMMISSIONED` vs `SAFE_TO_DECOMMISSION`/`BLOCKED_*`）；
- 异常或并发冲突下最终可见的版本状态只有两种：保持原状态（拒绝），或完整的
  `REVOKED` 终态（成功），可通过 `GET /api/keys/versions` 与 `/references` 核验。

## 6. REST 接口

| 方法与路径 | 说明 |
|------------|------|
| `POST /api/keys/encrypt` | body `{"plaintext":"..."}`，用当前 ACTIVE 加密 |
| `POST /api/keys/decrypt` | body `{"ciphertext":"v..:..."}`，按信封版本解密 |
| `POST /api/keys/rotate` | 原子轮换，返回 `{previousVersion, activeVersion}` |
| `POST /api/keys/revoke` | body `{"version":2}`，吊销指定版本（无条件强制手段） |
| `GET  /api/keys/versions` | 列出全部版本及状态/时间戳，供审计核验 |
| `POST /api/keys/migrate?limit=100` | 执行一批全量迁移；不传 limit 用配置默认值，传 `0` 表示全量 |
| `GET  /api/keys/migrate/progress` | 实时迁移进度 |
| `POST /api/keys/migrate/from/{v}?limit=100` | 按来源版本定向清理一批；分批/续跑/幂等语义同全量迁移 |
| `GET  /api/keys/versions/{v}/references` | 单个版本引用统计与下线预检结论 |
| `GET  /api/keys/references` | 全部版本引用统计快照（同一份数据快照，互相一致） |
| `POST /api/keys/decommission` | body `{"version":2}`，受门禁保护的安全下线 |

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

安全下线闭环（统计 → 定向清理 → 下线）：

```bash
# 1) 看依赖：v1 还有 6 条数据引用，被 BLOCKED_BY_REFERENCES 挡住
curl -s localhost:8080/api/keys/versions/1/references
# {"version":1,"state":"RETIRED","referenceCount":6,"active":false,
#  "safeToDecommission":false,"reason":"BLOCKED_BY_REFERENCES"}

# 2) 直接下线被门禁拒绝（原因可区分）
curl -s -XPOST localhost:8080/api/keys/decommission -H 'Content-Type: application/json' \
  -d '{"version":1}'
# {"error":"VERSION_STILL_REFERENCED","message":"key version 1 is still referenced by 6 data record(s)"}

# 3) 定向清理 v1（可分批：?limit=100，中断后重复调用续跑）
curl -s -XPOST 'localhost:8080/api/keys/migrate/from/1'
# {"fromVersion":1,"toVersion":2,"sourceTotal":6,...,"remaining":0,"completed":true}

# 4) 引用归零后再下线，放行进入 REVOKED 终态
curl -s -XPOST localhost:8080/api/keys/decommission -H 'Content-Type: application/json' \
  -d '{"version":1}'
# {"version":1,"state":"REVOKED",...}
```

## 7. 迁移与下线的验证方法（测试如何核验）

`MigrationServiceTest` 覆盖了可核验的完整路径：

1. 准备 10 条 v1 数据后轮换到 v2；
2. 分批 `migrate(4)`、`migrate(4)`、`migrate(4)`，断言每批 `migrated/remaining/percent`，
   验证**中断续跑**（40% → 80% → 100%）；
3. 再连续执行两轮全量迁移，断言 `migrated=0, skipped=全部`、密文字节不再变化，
   验证**幂等**；并断言每条记录明文仍与最初一致（明文含义不变）且只有单一一致状态；
4. 先吊销 v1 再迁移，断言 `failed>0`、`completed=false`、失败记录密文原样保留；
5. 迁移途中再次轮换，断言续跑自动指向最新版本并最终全部收敛。

本轮新增能力的核验路径：

- `RotationCryptoConcurrencyTest`（**确定性并发时序**）：通过存储切换临界区内的
  测试栅栏，把轮换精确挂在“旧版本已 RETIRED、新版本尚未 ACTIVE”的瞬间：
  (1) 12 线程 600 次加密在该点同时发起，0 失败、全部落在切换后版本且可解；
  (2) 同一点注入存储故障，8 线程 400 次加密 0 失败，回滚后恰好一个 ACTIVE、
  历史数据可解、失败码为 `ROTATION_FAILED`、版本号可复用。对照实验：换回旧的
  两步非原子实现时这两个用例分别必现 600/400 次失败；
- `KeyManagerConcurrencyTest`：并发轮换串行化、唯一 ACTIVE、无重复版本；
  轮换↔加解密采用分阶段交错（每轮“加密→轮换→加密”），1600 条消息全部可解、
  版本 1..5 确定性地都被使用，并有看门狗全程断言“恰好一个 ACTIVE”；
- `VersionLifecycleServiceTest`：引用计数准确、预检结论可区分（ACTIVE 挡住 vs
  引用挡住）、统计随每批迁移实时收敛、全量快照内部自洽、未知版本 404 语义；
- `DecommissionServiceTest`：ACTIVE 拒绝（`VERSION_IS_ACTIVE`）、引用未清零拒绝
  （`VERSION_STILL_REFERENCED`）且拒绝后旧数据仍可解密、未知版本拒绝、重复提交
  一致返回 `REVOKED_VERSION`、多代旧版本各自“清理 → 引用归零 → 下线”互不干扰；
- `TargetedMigrationTest`：千条级（1200 条）定向清理分批中断续跑（500+500+余量）、
  幂等重跑不改写密文、多代并存时只清理指定代、清理后引用精确归零、
  清理当前 ACTIVE/未知版本被拒绝、已吊销代清理失败隔离且原密文保留；
- `DecommissionConcurrencyTest`：16 线程并发下线同一版本**只有一个成功**、
  其余一致 `REVOKED_VERSION`；下线与定向清理并发竞跑时下线被稳定挡住直到引用
  清零，终态不存在“版本已停用但历史数据打不开”的窗口；
- `WebDecommissionApiTest`：统计/定向清理/下线全 REST 走查，失败原因与
  HTTP 状态码一一对应。

## 8. 关键配置项（`application.properties`）

| 配置键 | 默认值 | 说明 |
|--------|--------|------|
| `keylifecycle.aes-key-bits` | `256` | AES 密钥位宽，仅允许 128/192/256 |
| `keylifecycle.gcm-iv-bytes` | `12` | GCM 随机 IV 长度（字节） |
| `keylifecycle.gcm-tag-bits` | `128` | GCM 认证标签长度（位） |
| `keylifecycle.migration-batch-size` | `100` | `/migrate` 未显式传 `limit` 时的默认批量大小 |
| `logging.level...cryptokeylifecyclejava` | `INFO` | 打印密钥版本、操作类型与判定依据 |

## 9. 测试与日志

```bash
mvn test            # 全离线运行，共 48 个用例
```

覆盖场景：AES/GCM 往返与随机 IV、密文篡改/IV 篡改/错误密钥、信封畸形输入、
密钥状态机、**并发轮换**（16 线程串行化、唯一 ACTIVE、无重复版本）、
**轮换与加解密确定性并发**（栅栏挂起切换临界瞬间：600/400 次并发加密 0 失败；
切换中途故障回滚后 0 失败、恰好一个在用版本、`ROTATION_FAILED` 可区分、
版本号可复用）、**轮换与加解密分阶段交错压测**（1600 条消息全部可解、
版本 1..5 都被使用、全程恰好一个 ACTIVE）、**迁移中断续跑/幂等/
跨轮换续跑/吊销源版本失败隔离**、**并发迁移收敛**、数据篡改端到端拒绝、
**版本引用统计与下线预检**、**安全下线门禁与重复/并发拒绝**、
**千条级定向清理中断续跑与多代收敛**、**下线与清理并发竞争**，
以及 REST 层状态码与原因码的区分。

单测与组件日志统一输出三要素，便于审计：

```text
version=<密钥版本> op=<ENCRYPT|DECRYPT|ROTATE|REVOKE|MIGRATE|CLEANUP|REFERENCES|DECOMMISSION|...>
basis=<判定依据，如 GCM_TAG_MISMATCH / ATOMIC_SWITCH / REFERENCES_ZERO / STILL_REFERENCED>
result=<PASS|REJECTED|...>，失败时带 reason=<原因码>
```

## 10. 代码结构

```text
crypto/    AesGcmCipher(加解密原语) CipherCodec(信封编解码)
           KeyVersion/KeyState(版本与状态) KeyStore/InMemoryKeyStore(线程安全存储)
           KeyManager(生命周期门面：状态机/原子轮换/加解密判定/下线门禁)
migration/ DataRecord/RecordStatus DataRepository(含 CAS 提交)
           MigrationService(全量+按来源版本定向清理) MigrationProgress/SourceCleanupProgress
lifecycle/ VersionLifecycleService(引用统计/下线预检/安全下线编排) VersionReferenceStats
error/     八类可区分异常（UNKNOWN_VERSION / REVOKED_VERSION /
           INTEGRITY_FAILURE / INVALID_INPUT / KEY_STATE_CONFLICT /
           ROTATION_FAILED / VERSION_STILL_REFERENCED / VERSION_IS_ACTIVE）
config/    KeyLifecycleProperties + Spring 本地装配（启动自动启用 v1）
web/       REST 控制器与统一异常处理（原因码 → HTTP 状态码，错误体无明文）
```
