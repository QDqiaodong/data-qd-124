# 跨库主体擦除（私有数据保留终止）v4

本文档描述第四个入口 `table-privacy-erase` 及其对连续发布台账
（[serial_release.md](serial_release.md)，下称 series 库）与关联风险审计库
（[linkage_audit.md](linkage_audit.md)，下称 audit 库）的改造。

## 范围与非目标（先读）

这是一次**私有数据的主体逻辑擦除**，不是新的匿名化或披露分析：

- 从两个**私有** SQLite 库中删除目标主体的台账历史行，并在 audit 库中删除
  包含目标、或无法证明与目标无关的整个 run 及其全部派生记录。
- 任务与墓碑**只保存按原 id 的 UTF-8 字节计算的 SHA256 摘要**；不保存明文 id，
  也不保存任何可逆编码。摘要只是**匹配键**：低熵 id 的摘要仍可被猜测，本工具
  **不把摘要宣称为匿名保证**，也不提供任何法律意义上的去标识认证。
- **不承诺**清除 SQLite 空闲页（free pages）、WAL 残留、数据库备份、文件系统
  快照或外部原始输入；这些由操作者按私有数据保管流程另行处理。
- 已存在的有效公开报告文件及台账中保存的报告字节**保持原样**，擦除不重写、
  不删除任何公开产物（验收以擦除前后 SHA256 一致断言）。
- 运行时仅使用 Python 标准库（含 `sqlite3`）。

## 入口与输入

```sh
table-privacy-erase \
  --ledger run/private/ledger.sqlite \
  --audit-db run/private/linkage_audit.sqlite \
  --request-id 2026-W46-termination-001 \
  --ids ids.json
```

- `--ids`：非空 JSON 字符串数组。顺序与重复元素被忽略（集合语义），每个 id 必须
  满足与源契约相同的标识符约束；文件受 8 MiB 输入上限约束，单次请求最多
  10000 个去重 id。
- `--request-id`：本次请求的稳定标识，用于 `--resume` 与 `--status`。
- `--resume`：**不需要再次提供 id 文件**，按原 request-id 续办未完成请求。
- `--status`：只输出不含明文 id 的任务状态，不修改任何数据。
- `--journal-mode {delete,wal}`：两库统一使用的 SQLite 日志模式；缺省为
  SQLite 的回滚日志（`delete`）。
- 退出码：成功 `0`；输入非法、绑定冲突、协议冲突（含墓碑/ pending 准入失败）
  一律 `2`，原因写 stderr。stdout 只有一行紧凑 JSON。

### 幂等与冲突

- 同一 `request-id` + 同一 id 集合（排列、重复不影响集合指纹）：任意次调用
  结果一致，已 `done` 的请求重复执行是纯空操作，**不会检查或删除后来新建的
  无关 run**。
- 同一 `request-id` 换用不同集合：拒绝（退出 2），既有任务状态与数据不变。
- 未知 `request-id` 的 `--resume`/`--status`：拒绝。

### 输出（无明文 id）

```json
{
  "request_id": "...",
  "state": "done",
  "id_count": 2,
  "id_set_fingerprint": "<sha256-of-canonical-digest-set>",
  "series_history_deleted": 4,
  "audit_runs_deleted": 1,
  "audit_index_rows_deleted": 4,
  "audit_rows_deleted": 18
}
```

`id_set_fingerprint` 是对“各 id 摘要按字典序排列后再做一次 SHA256”的结果，
用于同 request-id 的集合一致性校验，本身不含明文。

## 两库一对一绑定

首次擦除时，两个库被**持久地一对一绑定**。绑定信息写入各自的 `meta` 表：

| 键 | 内容 |
| --- | --- |
| `privacy_binding_token` | 两库共享的 256 位随机 token（`secrets.token_hex(32)`） |
| `privacy_binding_role` | `series_ledger` 或 `linkage_audit` |
| `privacy_binding_peer_path` | 伙伴库的绝对路径 |

**fail-closed 规则**（CLI 与 Python 写 API 走同一条构造路径，无法用旧 CLI 或
直接调用 `Store`/`AuditStore` 绕过）：

- 已绑定库再次打开时，**省略**伙伴参数 → 构造即失败（退出 2）。
- 传入**另一个** ledger/audit 路径（与 `peer_path` 不符）→ 构造即失败。
- 角色不符、绑定三元组不完整、两库 token 不一致 → 失败。
- **未绑定库的原有入口完全兼容**：`table-privacy-series` 与
  `table-privacy-linkage` 的旧参数形式在绑定发生前行为不变，回归测试保留。

绑定先写 audit 侧再写 ledger 侧。若在两次 `meta` 提交之间退出，重入时
`ensure_binding` 只在“已绑定一侧的回指路径与当前打开的伙伴完全一致”时补写
同一 token 完成配对；回指其他路径则拒绝，避免把已绑定库嫁接给陌生库。

## series 库改造

新增两张私有表：

| 表 | 内容 |
| --- | --- |
| `erase_tasks` | 每请求一行：`request_id`、集合指纹、去重 id 数、状态 `pending/done`、各阶段删除计数、创建/完成时间 |
| `tombstones` | `(id_digest, request_id)`：墓碑只存 SHA256 摘要 |

### 历史保留与写入准入

- 擦除删除目标 id 在 `history` 中的**所有版本所有行**；其他 id 的历史、批次号
  与版本序列原样保留。即使某群体身份被全部擦除，`next_version()` 仍取
  `MAX(version)+1`，下一版本连续。
- 墓碑是**永久**准入条件：新批次输入中任一 id 命中墓碑即拒绝；旧 `batch_id`
  重放若其输入携带墓碑 id，同样在触碰台账前拒绝（退出 2，状态不变）。
- 准入检查分两层：
  1. `publish()` 开头的只读预检，覆盖不可行分析与重放路径，保证任何携带墓碑
     id 的调用都不会推进台账；
  2. `insert_committed()` 的 `BEGIN IMMEDIATE` **事务内**复查 pending 与墓碑。
     写锁取得后看到的是最新已提交状态，因此“先读到旧状态、完成计算、再提交”
     的在途写者，只要擦除先完成，就一定在提交点失败——准入不依赖 CLI 入口检查。
- pending 期间一切新批次（不含目标的也一样）被拒绝；只有任务转 `done` 后
  无关主体才能恢复写入。

## audit 库改造

新增两张私有表：

| 表 | 内容 |
| --- | --- |
| `run_identity_index` | `(run_id, identity_index, id_digest)`：每个绑定后新 run 的**全部**输入主体摘要索引，与 run 在同一事务原子写入 |
| `erase_progress` | 每请求一行的阶段 2 恢复标记与删除计数；无明文 id |

### 新 run 的原子索引与准入

- 每个绑定后的新 run，`runs/slots/edges/outcomes/.../Hall` 全部行与
  `run_identity_index` 在**同一个 `BEGIN IMMEDIATE` 事务**内提交：run 要么
  完整带索引可见，要么不存在。**inconsistent run 也不例外**——其全部输入主体
  （含不属于 Hall 证人集合的身份）都进索引。
- 提交事务内通过只读 URI 打开绑定的 series 库，复查 pending 任务与墓碑。
  读检查发生在 audit 写锁取得之后，和 run 写入共享同一个串行化点。
- 计算（Dinic/SCC）完全在事务外完成；测试屏障也位于 `BEGIN IMMEDIATE` 之前，
  等待中的写者不持有任何排他锁。

### 擦除的保守判定（单事务）

对每个 run 分类：

1. **完整索引且不命中**任何目标摘要 → 逐字段保留（含 slots/edges/结论/
   possible categories/Hall 派生记录与索引本身）。
2. **索引命中**目标（无论该身份是否在 Hall 证人集合内）→ 删除整个 run 及其
   全部槽、边、结论、类别与 Hall 派生记录。
3. **绑定前的旧 run**：没有完整索引（索引行数与 `runs.identity_count` 不符，
   含完全无索引的历史库），无法证明与目标无关 → 首次擦除时**保守清除**。

`erase_progress` 与删除在同一事务提交，是阶段 2 的幂等恢复标记：续办时标记
已存在就直接返回存储计数、不再扫描或删除，因此完成后新建的 run 永远不会被
同一请求的重复 resume 误删。

## 提交顺序、恢复判据与锁/快照边界

series 库拥有请求状态机，因此**series 墓碑控制 linkage 的真实提交边界**。
一次擦除三个阶段：

1. **阶段 1（series，单事务）**：插入 `pending` 任务行、插入全部墓碑、删除
   匹配的 history 行、记录 `history_deleted`，一次提交。此后两库的写准入都
   关闭（audit 通过只读读取该 pending 状态）。
2. **阶段 2（audit，单事务）**：保守清除 + 写 `erase_progress`，一次提交。
3. **阶段 3（series，单事务）**：任务转 `done` 并记 `finished_at`。此后两库
   恢复无关主体写入；墓碑永久保留。

跨库没有、也不可能有两阶段提交，因此恢复只依赖**各自持久化的单侧标记**：

| 退出点 | 重启后看到的状态 | resume 行为 |
| --- | --- | --- |
| 阶段 1 提交前 | 无任务行 | 原请求重新开始 |
| 阶段 1 后、阶段 2 前 | series `pending`，audit 无 progress | 用墓碑摘要重跑阶段 2，再转 done |
| 阶段 2 后、阶段 3 前 | series `pending`，audit 有 progress | 跳过清除，直接转 done |
| 阶段 3 后 | `done` | 纯空操作，不触碰后来的新 run |

**锁与快照边界**：

- 每个库内部靠 `BEGIN IMMEDIATE` 把“准入判断 + 写入/删除”收进同一事务；
  SQLite 单库语义保证该事务对其他写者串行化。
- 跨库一致性靠 **pending 闸门 + 幂等单侧标记**，而不是假装两次单库 commit
  可以共同原子：阶段 1 一旦落盘，两库都拒绝新提交，直到阶段 3 完成。
- audit 侧对 series 的准入读取使用 `mode=ro` URI 连接，是一个独立快照读；
  它在 audit 写事务内执行，WAL 下读到最新已提交快照，回滚日志下读期间没有
  其他 series 写事务。真正的竞态闭环由 series 自己事务内的复查兜底。
- 允许每库一个正常写者与一个擦除进程并发。耗时分析/求解不持有跨库排他锁；
  在途写者即使计算完毕，只要擦除先返回 done，其提交点复查必失败。未命中
  主体在恢复完成后正常写入。验收用真实子进程 + 文件屏障
  （`TABLE_PRIVACY_GATE_ROOT`，就绪/等待/释放三个哨兵文件）暂停写者于
  “计算后、取写锁前”，不使用 `sleep` 猜时序；杀死进程用既有
  `TABLE_PRIVACY_CRASH_HOOK` 的 `os._exit(99)` 硬退出。

## 选定方案的代价

- **保守清除偏删除**：绑定前无完整索引的旧 run 在首次擦除时整体删除，即使
  它们实际上与目标无关。这是“无法证明无关即不保留”的显式取舍，换取不重建
  历史输入即可证明的义务边界。
- **墓碑永久增长且不回收**：墓碑是后续准入的依据，不能随任务 done 删除；
  长期运行会累积每个被擦除 id 一行 32 字节摘要。
- **摘要可猜测**：SHA256 不防字典枚举，墓碑只能做确定性匹配，不能当作匿名化。
- **跨库非原子**：两库在阶段之间存在持久化的 pending 窗口，期间全部无关写入
  也被拒绝；可用性让位于“不允许目标复活”。
- **空闲页/备份不在内**：删除后 SQLite 文件不会自动缩小，旧页可能残留旧数据
  字节；需要物理销毁时由操作者执行 `VACUUM`、密钥/备份轮换等外部流程。
- **路径绑定的运维约束**：绑定记录绝对路径，移动库文件后需在受控流程下重建
  绑定；工具本身不提供“改绑”，以防静默嫁接。

## 测试与验收映射

- `tests/test_erase.py`：库级 series/linkage/binding 语义（18 例）。
- `tests/test_erase_cli.py`：CLI、真实子进程屏障竞争、三个崩溃点 × 两种日志
  模式的 kill/resume 矩阵、公开报告 SHA 不变、无明文 id 输出、绑定 fail-closed。
- 既有 `tests/test_series*.py`、`tests/test_linkage*.py` 全部保留并通过，
  覆盖未绑定库的旧入口回归。
