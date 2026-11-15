# 单次发布的流式架构（1 GiB / 百万行）v1.1

本文档补充 [v1 单次契约](contract.md)：契约限额提升为 **JSON ≤ 1 GiB、records ≤ 1,000,000、
max_suppressed ≤ 1,000,000、k ≤ 10,000（不变）**，并描述如何用增量解析、磁盘中间层和流式
报告在 **256 MiB 地址空间**内完成全程，同时与内存参考实现 `model.analyze` 逐字段一致。
连续发布入口 `table-privacy-series` 及其限额（8 MB / 10000 行 / 预算 10000）**完全不变**，
仍走 `common.read` + `parse_input` 的原有路径。

## 目标与非目标

- 目标：单次入口 `table-privacy` 在百万行、高基数 id/category、源文件与报告都大于物理
  内存（>256 MiB）时仍正确运行；任何输入或计算失败都以退出码 2 结束、保全旧报告、
  stdout 不出现半份报告、私有临时数据被清理。
- 非目标：不改变九候选、排序、预算语义；不提高 k 上限；不改变连续发布协议；不引入
  标准库之外的依赖；不承诺并发发布或断电恢复（单次入口的原有边界，见 contract.md）。

## 流水线总览

```
源文件(≤1 GiB) ──▶ streamjson 增量解析 ──▶ SQLite 私有工作库(磁盘中间层)
                                              │
                                              ├─ 9 × GROUP BY 候选计数
                                              └─ 选定候选的保序游标 ──▶ 双流报告写出
                                                                          ├─ 紧凑字节 → stdout
                                                                          └─ 缩进字节 → 临时文件 → os.replace → 报告文件
```

内存中只驻留：当前 JSON 词法单元（字符串 ≤ 4096 字符、数字 ≤ 4300 位）、一批 1000 行记录、
SQLite 页缓存（约 2 MiB）与写出缓冲（1 MiB）。实测峰值 RSS 约 30–40 MiB。

### 1. 增量解析（streamjson.py）

- **分块读取**：默认 1 MiB 一块；`TABLE_PRIVACY_CHUNK_BYTES` 仅供测试改小块。读到的
  每个字节都先进入 SHA-256（**摘要覆盖源文件全部字节**，与 `common.read` 一致），再解码。
- **增量解码**：前 4 字节用 `json.detect_encoding` 判定编码（与 `json.loads(bytes)` 完全
  一致，utf-8 / utf-8-sig / utf-16 / utf-32 行为相同），之后用增量解码器处理**跨块
  UTF-8 字符**；非法/截断字节序列抛 `UnicodeDecodeError`（ValueError 子类）。
- **位置化词法匹配**：字符串/数字用锚定正则直接在缓冲区当前位置匹配，不复制子串；
  字符串在缓冲未闭合时继续拉块。字符串解码上限 4096 字符（契约最大 128，超出必拒）、
  原始转义上限 6×4096+2 字节，数字上限 4300 字符（对齐 CPython int 转换上限），因此
  缓冲需求有常数上界。转义（含 `\uXXXX` 与代理对）由 `json.loads` 逐段解码，**跨块
  转义序列**自然成立。
- **契约状态机**：顶层只接受 `{k, max_suppressed, records}`，记录只接受
  `{id, age, postal, category}`；**records 可以先于参数出现**，参数在出现处校验
  （k∈[2,10000]、max_suppressed∈[0,1000000]）。records 流式逐行校验（ident/年龄上界/
  邮编正则），每 1000 行批量交给 SQLite 汇；第 1,000,001 行报 `expected bounded array`。
- **拒绝语义保持**：重复键（按解码后键名，任意对象层）、未知字段、非有限数
  （`NaN`/`Infinity`/`-Infinity`，报文与原来一致）、布尔/浮点年龄、空/超长/含控制字符
  标识、非法邮编、重复 id、空 records、**尾随垃圾**全部抛 ValueError → 退出码 2。
  错误消息文本尽量沿用原实现；个别路径（如结构错误）消息措辞不同但拒绝一致。

### 2. 磁盘中间层（engine.py 的 SQLite 工作库）

- 私有临时目录（`tempfile.mkdtemp`，尊重 TMPDIR）内建 `work.sqlite3`：
  `ids(id BLOB PRIMARY KEY) WITHOUT ROWID` 负责**精确**重复 id 拒绝（`IntegrityError`
  → `duplicate source row ID`）；`records(age INTEGER, postal TEXT, category BLOB)`。
- id 与 category 以 **surrogatepass UTF-8 BLOB** 存储：任何 Python str（含孤立代理项）
  都能无损往返；BLOB 的 memcmp 序与 Python 码点序一致，排序与原实现相同。
- `journal_mode=OFF`、`synchronous=OFF`（私有草稿库，崩溃即弃）、`temp_store=FILE`：
  GROUP BY 排序溢出到磁盘临时文件，内存驻留有界。SQLite 自身的临时排序文件在语句
  结束时自动删除；工作库随私有目录在 finally 中整体清除。

### 3. 九候选与排序一致性

- 泛化标签用 SQL 表达式复刻 `generalize.bucket`：
  年龄 `CAST(age AS TEXT)` / `((age/10*10)||'-'||MIN(120,age/10*10+9))` / `'*'`；
  邮编 `postal` / `SUBSTR(postal,1,3)||'**'` / `'*'`。定义域已校验（age∈[0,120] 整数、
  postal 恰 5 位 ASCII 数字），与 Python f-string 结果逐字节相同。
- 每候选一次 `GROUP BY` 聚合出 `suppressed` 与“至少一组 ≥ k”；可行性与
  `(ordinal_generalization_cost, suppressed, age_level, postal_level)` 排序在 Python 侧
  用同一 `Fraction` 元组取 `min`，与 `model.analyze` 完全一致。
- 选定候选用窗口函数一次取出保留类的 `(age, postal, category, count, class_size)`，
  `ORDER BY age, postal, category`（BINARY 排序 = 码点序 = Python 字符串序），
  等价类与 released_rows 都由该保序游标流式产出：**重复行逐条保留**、
  `equivalence_classes` 完整（size、distinct_categories、category_counts 按类别排序）。

### 4. 流式报告与失败模型

- 报告不再整表驻留：一个 token 级 JSON 写出器同时喂给**紧凑**（json.dumps 默认分隔符
  `', '`/`': '`）与**缩进**（`indent=2`）两路字节流，键按 sort_keys 顺序产生；字符串
  转义逐字符对齐 CPython `ensure_ascii=False` 的行为。小表与 `analyze` 的规范序列化
  **逐字节相等**（测量脚本断言）。
- 写出顺序：先在私有目录生成紧凑字节、在输出目录临时文件生成缩进字节 →
  `os.replace` 原子替换报告 → 最后把紧凑字节流式拷贝到 stdout。因此：
  - 输入或计算失败（含写盘失败）：旧报告原样保留，stdout 为空；
  - stdout 只在报告完整落盘后才开始写，**不会出现半份报告**；
  - 输出为符号链接拒绝、源与输出相同拒绝（沿用原语义）。
- 私有临时目录（含 id 与 category 的工作库、紧凑中间文件）在 finally 中删除；
  删除失败会在 stderr 告警但不掩盖主结果。孤立代理项 category 若进入发布行，
  UTF-8 编码失败（ValueError）→ 退出 2 且旧报告保留——与原实现在 `json.dump`
  阶段失败的可观察行为一致；若该行被抑制则报告不含它，正常成功。
- 退出码：成功 0；输入或计算失败 2（`ValueError/TypeError/KeyError/OSError/
  OverflowError/RecursionError/sqlite3.Error` 均映射到 2，stderr 给出原因）。

## 限额对照

| 项 | 单次（新） | 单次（旧） | 连续发布（不变） |
| --- | --- | --- | --- |
| 源 JSON | 1 GiB | 8 MB | 8 MB |
| records | 1,000,000 | 10,000 | 10,000 |
| max_suppressed | 1,000,000 | 10,000 | 10,000 |
| k | 10,000 | 10,000 | 10,000 |

`model.analyze` 保留为内存参考实现（小表、测试、连续发布首轮一致性对照），其参数校验
限额同步到新契约；`series.py` 以默认参数调用 `parse_input`，保持旧限额。

## 测量（Linux）

```sh
scripts/measure_linux.sh [工作目录]
```

脚本依次验证：

1. **小表逐字段对照**：随机小表（字段乱序、records 先于参数、随机转义/空白、
   utf-8/utf-8-sig/utf-16 编码、1–4096 字节读块）与原 `analyze` 逐字段且逐字节一致；
   跨块重复键/重复 id、末尾坏记录、尾随垃圾及全部拒绝语义（布尔年龄、非有限数、
   未知字段、重复键等）→ 退出 2、旧报告保全、stdout 为空。
2. **中表（6 万行）全字节对照**。
3. **写盘失败**：输出父路径不是目录、输出为符号链接/目录、源=输出、不可写目录
   （非 root）、RLIMIT_FSIZE 下中间层写失败与报告写半途失败——均退出 2、旧报告
   保全、stdout 为空、私有临时数据清零。
4. **限额**：第 1,000,001 行拒绝；1 GiB+1 字节拒绝；恰 1 GiB 不触发限额（按非法
   JSON 拒绝）；k=10001、max_suppressed=1000001 拒绝（在 1 中）。
5. **大表**：100 万行、id/category 全高基数（各 128 字符）、源 ≈ 292 MiB、
   报告与 stdout 均 >256 MiB，在 `ulimit -v 262144`（256 MiB 地址空间）内完成；
   校验退出 0、峰值 RSS < 256 MiB、报告/stdout 完整（首尾结构、`input_rows`、
   `released_count`、`suppressed_rows`、`selected`、`source_sha256` 与源文件
   sha256sum 一致——**SHA 覆盖源全部字节**）。

大表运行需要约 4 GiB 临时磁盘（工作库 + 两路报告中间文件 + 输出），脚本在空间不足时
跳过该步并说明。临时目录可用 `TMPDIR` 指定；SQLite 临时排序文件用 `SQLITE_TMPDIR`。

## 测试钩子

- `TABLE_PRIVACY_CHUNK_BYTES`：解析读块字节数（默认 1 MiB），仅用于跨块行为测试。
- 连续发布的 `TABLE_PRIVACY_CRASH_HOOK` 不变，见 [serial_release.md](serial_release.md)。
