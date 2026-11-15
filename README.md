# data-qd-124 · 表格隐私泛化评估

Global recoding search for k-anonymous synthetic tables。业务输入、计算和当前边界详见 [数据契约](docs/contract.md)。

## 安装与演示

Python >=3.11，运行和测试仅用标准库；先确认 `python3 --version`。
每仓建立独立环境，构建工具锁版本。首次安装无公共缓存时可能联网；业务运行不访问网络。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-build.lock
.venv/bin/python -m pip install --no-build-isolation --no-deps .
.venv/bin/python -m pip check
.venv/bin/table-privacy --source fixtures/input.json --output run/report.json
.venv/bin/python -m unittest discover -s tests -v
```

无 venv 时也可用 `PYTHONPATH=src python3 -m unittest discover -s tests -v` 直接运行测试
（运行时仅标准库）。

### 同一群体的连续发布（v2）

单次入口之外，新增私有 SQLite 台账驱动的连续发布入口 `table-privacy-series`。输入仍是
上面的 v1 契约，另需唯一批次号、私有台账路径与公开报告路径：

```sh
.venv/bin/table-privacy-series \
  --source fixtures/series/counterexample_round1.json \
  --batch-id round-1 --ledger run/private/ledger.sqlite \
  --report run/public/round1.json
```

它用私有 id 连接跨轮身份，按“完整历史标签序列 + 本轮泛化桶”做联合 k 分组；缺席与抑制都
落统一空标签，新 id 的过去补空。九候选、预算与排序与单次契约一致，第一轮结果与单次分析
逐字段相同。SQLite 提交与文件替换之间任意退出都能在重启后幂等恢复，恢复完成前拒绝下一
批；同批次同 SHA/参数重放返回同一版本，冲突拒绝；历史仅追加一次且已公开版本不可回滚。
公开报告与 stdout 不含 id、身份映射或个体轨迹。威胁模型、台账结构与协议细节见
[连续发布设计](docs/serial_release.md)，反例与身份场景 fixtures 在 `fixtures/series/`。

本地已有wheel时，安装构建工具可加 `--no-index --find-links <公共wheel缓存目录>`。
修改源码后重新安装。本仓不共享其他仓环境，不依赖Docker、外部账号或持续服务。

### 关联风险审计（v3）

第三个入口 `table-privacy-linkage` 把**单次公开 schema-1 报告**与一份**合成辅助
身份 JSON 数组**（`id/age_min/age_max/postal_prefix`）导入**私有 SQLite 审计库**。
它不读私有源表，也不读 series 台账；辅助表被假设恰好覆盖全部已发布身份且 id 唯一，
辅助行数与已发布容量不一致按非法输入拒绝（退出 2、保旧库），不猜概率。

```sh
.venv/bin/table-privacy-linkage \
  --report run/public/round1.json \
  --helpers fixtures/linkage/helpers_forced.json \
  --audit-db run/private/linkage_audit.sqlite
```

公开 `(age,postal,category)` 计数作为容量槽（重复槽位不展开）；辅助年龄区间与邮编
前缀同时与桶标签相交才连边，category 不参与连边。在“每人恰配一槽、所有容量恰满”
的满匹配空间上，以一次 Dinic 最大流加一次残量 SCC 判定每条兼容边是否可进入某个
满匹配，并求每人跨全部满匹配的可能 category 集合：仅一种时记强制暴露；无满匹配记
`inconsistent` 并保存 Hall 证据（身份集合、邻接槽联合容量与缺口）。支持 2000 身份、
2 万兼容边，不枚举匹配、不逐边重求解；小图以回溯穷举（测试内展开槽位副本）逐边、
逐身份对照。审计库在完整求解后于单事务内写入双源 SHA、容量槽、兼容边、可能类别与
证据；stdout 只输出无 id 的聚合摘要。威胁假设、标签相交语义（含年龄 120、`*`、
前导零）与表结构见 [关联风险审计设计](docs/linkage_audit.md)，自制样例在
`fixtures/linkage/`（生成脚本 `scripts/build_linkage_fixtures.py`）。

输入JSON最多1 GiB、records最多一百万行、max_suppressed最多一百万、k最多一万；拒绝重复键、
非有限数值和未定义字段；源字节SHA256随结果保留。单次入口为流式架构：增量解析（records可
先于参数）、SQLite磁盘中间层、流式报告，256 MiB地址空间内可处理源与报告都超过内存的输入，
结果与内存参考实现model.analyze逐字段一致（见 [流式设计](docs/streaming.md)，测量脚本
`scripts/measure_linux.sh`）。连续发布入口限额不变（8MB/一万行/预算一万）。
输出是可独立读取的JSON；成功后原子替换，输入/计算失败退出2并保留旧报告，stdout不出现半份
报告，私有临时数据随进程清理。
输入和输出不得相同，输出符号链接拒绝。单次入口面向独立批次，不承诺并发发布或断电恢复；
断电可恢复的连续发布由上文 `table-privacy-series` 的台账协议承担（仍限定单写者）。
同输入重跑不累加。测试使用临时目录，运行产物在忽略的run/。

src/table_privacy/model.py 为业务模型（内存参考实现与共享输入校验），generalize.py 构建
泛化桶；streamjson.py 增量解析契约输入，engine.py 以SQLite磁盘中间层与流式报告执行单次
发布，cli.py 为单次入口；series.py 实现跨轮联合分组、SQLite台账与持久发布协议，
series_cli.py 为连续发布入口；linkage.py 实现公开报告×辅助身份的容量槽匹配、Hall
证据与审计库写入，linkage_cli.py 为关联风险审计入口；common.py 提供受限JSON及报告发布。
fixtures 为明确自制样例，代码与样例采用MIT许可。

## 业务与样例结果

9种全局recoding中选年龄十岁段/邮编前3位；保留4行、抑制1行，每组至少2行。
generalize.py构建等价类，model.py选择策略并报告类别单一组；不把k-anonymity称为隐私保证。
