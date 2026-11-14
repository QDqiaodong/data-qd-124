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

输入JSON最多8MB，拒绝重复键、非有限数值和未定义字段；源字节SHA256随结果保留。
输出是可独立读取的JSON；成功后原子替换，输入/计算失败退出2并保留旧报告。
输入和输出不得相同，输出符号链接拒绝。单次入口面向独立批次，不承诺并发发布或断电恢复；
断电可恢复的连续发布由上文 `table-privacy-series` 的台账协议承担（仍限定单写者）。
同输入重跑不累加。测试使用临时目录，运行产物在忽略的run/。

src/table_privacy/model.py 为业务模型（单次分析与共享输入校验），generalize.py 构建
泛化桶；series.py 实现跨轮联合分组、SQLite台账与持久发布协议，series_cli.py 为连续发布
入口，cli.py 保持原单次数据链路；common.py 提供受限JSON及报告发布。
fixtures 为明确自制样例，代码与样例采用MIT许可。

## 业务与样例结果

9种全局recoding中选年龄十岁段/邮编前3位；保留4行、抑制1行，每组至少2行。
generalize.py构建等价类，model.py选择策略并报告类别单一组；不把k-anonymity称为隐私保证。
