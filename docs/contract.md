# Global recoding for a synthetic table v1

为离线数据发布研究者评估一个明确的k-anonymity泛化/抑制策略。仅处理原创合成表格，不接真实个人数据。
输入k=2..10000、max_suppressed=0..10000、records<=10000非空；每行id/age/postal/category。
id唯一，age整数0..120，postal恰5位ASCII数字（保留前导0），category非空文本<=128字符。
id只用于拒绝重复输入，不出现在发布记录/类别报告中；原输入文件仍由调用者保留，不被销毁。

准标识符恰为age和postal；category作为保留属性，不纳入k分组。
age层级0=精确年龄、1=十岁段（120→120-120）、2=*；postal层级0=完整、1=前3位+**、2=*。
枚举9种全局recoding，对每个组合按泛化age/postal分组，整组大小<k的记录被抑制。
可行要求至少保留1组且抑制总数<=预算；全抑制不作为成功。不可行是正常报告feasible=false。

固定策略先最小化ordinal_generalization_cost=(age_level+postal_level)/4，再最小化抑制数，
最后按age_level、postal_level打破平局。这个成本是人为的层级代价，不是测得的真实信息损失，
不声称全域最优匿名化；最优仅针对这9个候选及明确排序。会展示每候选成本/抑制数/可行性。
输出无源ID的泛化行（保留重复行）、等价类大小、category分布/多样性及总抑制数；不列被抑制源ID。
不强制l-diversity或t-closeness；类别单一的k组仍可能暴露属性，明确保留诊断而非宣称安全。
也不防外部辅助信息、重复发布组合攻击，不等于差分隐私或法律去标识认证。

fixture选age_level1/postal_level1、cost1/2，保留4行两组（20-29/123**、40-49/987**），
抑制1行；第二组category单一。交换输入顺序不改变发布内容。当前没有泛化树配置、真实标识脱敏、
差分隐私噪声、多文件关联或外部发布接口。JSON中可能保留敏感category；只能按本合成契约解释。
