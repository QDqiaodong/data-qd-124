# 同一合成群体的连续发布（私有 SQLite 台账）v2

本文档在 [v1 单次契约](contract.md) 之上，描述对**同一合成群体多轮发布**的扩展。
单次入口 `table-privacy` 与其输入/输出契约保持不变；连续发布使用独立入口
`table-privacy-series` 和一个永不公开的 SQLite 台账。

## 入口与输入

```sh
table-privacy-series \
  --source round3.json \
  --batch-id 2026-W46-round3 \
  --ledger run/private/ledger.sqlite \
  --report run/public/round3.json
```

- `--source`：**完全沿用 v1 输入契约**（`k`、`max_suppressed`、`records`，每行
  `id/age/postal/category`，同样的边界、重复 id 拒绝、8MB 与严格 JSON 限制）。
- `--batch-id`：调用者给出的唯一批次号；同一批次号的重试语义见下。
- `--ledger`：私有 SQLite 台账路径，包含 id 与历史标签，**绝不能进入公开目录**。
- `--report`：公开报告落盘路径；其内容同时写到 stdout。台账、报告、输入三者路径
  必须互不相同，报告与台账路径拒绝符号链接。

退出码与单次入口一致：成功 `0`，输入或协议冲突 `2`（stderr 给出原因）。

## 威胁模型（刻意收窄）

仅防御**观察者把同一身份在各轮的 age/postal 组标签串联起来**这一种攻击。

- 私有 `id` 只用于在台账内连接跨轮身份，不出现在任何公开报告或 stdout 中。
- 缺席（本轮无该 id）与抑制（联合组不足 k）都记录为**同一个统一空标签** `""`，
  观察者无法区分这两种情形。
- 新 id 的过去各轮一律补空标签，因此“新进入群体”与“历史上一直缺席/被抑制”在
  标签序列上不可区分。
- **不承诺** `category` 的安全（它是保留属性，可能单一化而暴露属性），也不防御
  外部背景知识、多文件关联或把 category 与外部信息结合的攻击。这不是差分隐私，
  也不是法律意义上的去标识认证。

## 联合分组算法

对每一轮仍枚举 v1 的 **9 个**全局 recoding（age/postal 各 3 级），预算
`max_suppressed`、候选排序（先 `(age_level+postal_level)/4`，再抑制数，再级别
平局）与“至少保留一组、全抑制不算成功”全部不变。区别只在分组键：

1. 从台账取出每个 id 既往各轮的标签序列（最旧在前）。
2. 对本轮每个候选，把每行按
   **（完整历史标签序列，本轮泛化桶）** 联合分组；本轮桶序列化为
   `"<age标签>|<postal标签>"`，`|` 不会出现在桶标签内。
3. 整个联合组大小 `< k` 则该组全部记录抑制（本轮标签记空）。
4. 选定最优候选后，公开输出把共享同一本轮桶的联合组合并，因此公开报告的
   `released_rows / equivalence_classes` 结构与 v1 完全一致；历史如何切分仅存在于
   私有台账。

第一轮没有历史时，联合分组退化为 v1 的单轮分组，结果与单次 `analyze` 逐字段一致
（除 `privacy_scope` 文案）。

## 私有台账结构

| 表 | 内容 |
| --- | --- |
| `meta` | 台账 schema 版本等键值 |
| `batches` | 每批次一行：`batch_id`、单调 `version`、`source_sha256`、`k`、`max_suppressed`、公开报告绝对路径、状态 `committed/published`、报告全文及其 SHA256、时间戳 |
| `history` | `(version, id, label)` 主键：每个 id 在每轮恰好一行，标签为本轮桶或统一空标签 |

约束保证：`version` 唯一且单调；同一 `(version,id)` 不可重复插入；状态只允许
`committed/published`。台账含 id 与个体轨迹，按私有数据保管。

成功发布后，为**历史全部 id** 追加本轮标签：在场者记其桶（被抑制则空标签），
缺席者记空标签；新 id 只插入本轮行，其过去通过算法侧补空体现，不回填历史行。
历史表只追加，已发布版本不可回滚、不可改写。

## 单写者持久发布协议

假设同一台账只有一个写者。一次发布在 SQLite 事务与文件替换之间的任意点退出，
重启后都能恢复且结果确定：

1. **分析**（无副作用）：读取台账历史并跑 9 候选。不可行则直接返回
   `feasible=false`、`version=null` 的报告，**不推进台账、不创建文件**。
2. **提交（committed）**：在单个 `BEGIN IMMEDIATE` 事务内插入 `batches` 行与全部
   `history` 行后提交。事务边界保证历史标签要么整轮可见、要么完全不可见，
   不会漏算或重复追加。
3. **替换文件**：用同目录临时文件 + `fsync` + `os.replace` 原子落盘，写入字节即
   台账中存储并哈希的字节。
4. **标记（published）**：另一个短事务把状态改为 `published`。

崩溃恢复（在下一次调用开头自动执行，作用于最新批次）：

- 停在步骤 2 之后、3 之前：台账为 `committed` 且无文件 → 依据台账重写文件再标记。
- 停在步骤 3 之后、4 之前：文件已原子就位、状态仍为 `committed` → 对账确认字节
  一致后仅补状态，不重写、不重复追加历史。
- 已是 `published`：仍把磁盘文件与台账哈希对账，被篡改或缺失则按台账复原。

恢复未能完成（例如报告目录不可写）时抛出错误，**拒绝开始下一批**；台账中最新
批次停留在 `committed`，重复调用直至恢复成功。恢复与重放都是幂等的。

## 重放与冲突

- 同一 `--batch-id` 且源字节 SHA256、`k`、`max_suppressed`、报告路径完全相同：
  返回台账中同一 `version` 的同一份规范字节（幂等重试，不新增批次或历史行）。
- 同一 `--batch-id` 但上述任一项不同：判定冲突，拒绝并以退出码 2 返回，台账不变。
- 新批次号复用了已发布批次的报告路径，或目标文件已存在：拒绝，避免覆盖已公开
  版本。

## 公开报告与脱敏

公开报告（文件与 stdout 同源字节）字段：

```json
{
  "schema_version": 2,
  "batch_id": "...",
  "version": 3,
  "source_sha256": "...",
  "result": { "feasible": true, "selected": {...}, "released_rows": [...], ... }
}
```

- 携带批次号与单调版本号；不可行时 `version` 为 `null` 且不落盘文件。
- `result` 内字段沿用 v1；任何公开字节都不含 id、id↔桶映射或个体跨轮轨迹。
- 落盘内容必须与台账 `report_json/report_sha256` 一致，恢复与重放都会强制对账。

## 非目标与运维假设

- 不加密台账、不管理文件权限；私有目录的访问控制由操作者负责。
- 恢复保证覆盖进程在任一步骤被杀死/退出（测试用 `os._exit` 模拟 SIGKILL）：
  报告文件写入前做了 `fsync` 并经 `os.replace` 原子替换。未额外对父目录做
  `fsync`，因此对整机掉电后文件系统层面的目录项持久性不作超出操作系统自身
  原子替换语义之外的承诺。
- 测试钩子 `TABLE_PRIVACY_CRASH_HOOK=after_db_commit|after_file_replace` 会以
  `os._exit(99)` 硬退出模拟 SIGKILL/断电，仅供测试，生产环境不要设置。
- 运行时仅用 Python 标准库（含 `sqlite3`）。

## v4 迁移：主体擦除与绑定（见 [privacy_erase.md](privacy_erase.md)）

- 台账新增 `erase_tasks` 与 `tombstones` 两张表，由 `table-privacy-erase`
  管理；墓碑只存 id 的 SHA256 摘要，不存明文。旧台账文件打开时自动补建，
  既有批次与历史行不受影响。
- 首次擦除会把本台账与一个 linkage audit 库**一对一持久绑定**。绑定之后：
  - `table-privacy-series` 与直接使用 `series.Store` 的写入口都必须传入
    `--audit-db`（构造参数 `audit_path`），省略或换库即 fail-closed（退出 2）；
  - 有 `pending` 擦除任务时新批次一律拒绝；任务 `done` 后无关主体恢复写入；
  - 含墓碑 id 的新批次与旧批次重放永久拒绝（退出 2），准入在写事务内复查，
    不依赖 CLI 入口检查。
- **未绑定台账的旧调用方式完全兼容**，无需任何参数变更。
- 擦除只删除私有 `history` 行并立墓碑；`batches`、版本序列、台账内报告字节
  与已落盘公开报告均保持原样（擦除前后 SHA256 不变）。全部身份被擦后
  下一批次的 `version` 仍在 `MAX(version)+1` 上连续。
