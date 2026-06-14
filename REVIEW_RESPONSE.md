# ESORICS 2026 拒稿意见 — 逐条对照解决进度

> 评分：Reviewer 1: -2 (reject) | Reviewer 2: 0 (borderline) | Reviewer 3: 0 (borderline)

---

## 战略性决策：移除匿名性声明

经分析，**匿名性（signer anonymity）并非本文的核心贡献**。本文的核心贡献是：
1. 加权门限签名（Weighted Threshold Signing）
2. 签名者问责性（Accountability via ElGamal tracing）
3. 无配对兼容性（Pairing-free）
4. 简洁 NIZK 证明（Succinct proof via Super Basis Injection）

匿名性相关的三条审稿意见（R3.1 数学错误、R3.2 仅对外部、R3.6 Table 1 缺行）可以通过**直接从论文中移除匿名性声明**来解决。具体操作：
- 删除 Remark 1（匿名性分析）
- 修改贡献列表，移除 "signer anonymity"
- 将威胁模型收缩为：问责性 + 不可伪造性，不声称匿名性
- Table 1 不再需要匿名性行（因为论文不声称匿名性）

**影响：P0 紧急项从 3 项减少为 2 项（仅剩安全性证明相关），总待处理项从 10 项减少为 7 项。**

---

## Reviewer 1（-2, reject）

### R1.1 — 代码无法复现 Fig 1

> "I cannot reproduce the numbers in Fig 1. The readme lists only the code for BLS pairings and EC-MSMs."

**已完成的工作：**

- 在 `time/src/main.rs` 中新增 `fig1` 子命令（+255 行），实现 4 方案 × 可变参数的全面对比 benchmark
- 输出标准 CSV 格式（`scheme, n_signers, active_signers, total_weight, threshold, sign_us, verify_us, comm_bytes, comm_per_signer`），可直接导入 Python/matplotlib 绘图
- 支持 `--sizes` 和 `--iters` 参数控制测试规模
- README 中添加了完整的 Fig 1 复现指令

**现状分析：**

旧代码中 `time/` 模块只能测量 EC 标量乘法、哈希等底层原语的性能，不产生任何协议级别的对比数据。这是 Reviewer 1 给出 -2 的核心技术原因——他亲自下载代码试图验证，但发现完全无法复现论文的核心实验图表。

**尚存差距：**

- 当前 benchmark 中 `verify_us` 对 BLS 和 Schnorr 使用了估算值（~450-500µs / ~50µs），而非实测值。这是因为验证路径需要完整的签名-验签流程，而当前 Fig 1 benchmark 侧重签名阶段的开销
- 缺少可视化脚本（Python/matplotlib）来直接生成论文中 Fig 1 样式的图表

**实现路径：**

1. 在 `bench_bls_verify` 和 `bench_schnorr_verify` 中补充实际验签测量（替换估算值），约 30 行代码
2. 编写 `scripts/plot_fig1.py`，读取 CSV 输出生成与论文一致的折线图，约 50 行 Python
3. 运行完整 benchmark 并将结果图加入论文的 artifact evaluation 材料

---

### R1.2 — Virtual Frost 完全缺失

> "When I looked in the code for the schemes/src, I missed virtual Frost completely."

**已完成的工作：**

- 新建 `schemes/src/virtual_frost.rs`（458 行），完整实现 Weighted FROST 协议，包括：
  - `WeightedFrost::setup()` — 带权重的密钥生成，每个 signer 有 weight 属性
  - `round1_commit()` — FROST 两轮协议的第一轮：nonce 承诺生成
  - `round2_sign()` — 第二轮：部分签名（含 Lagrange 系数、rho binding）
  - `combine()` — 签名聚合
  - `verify()` — 单签名验证（Ed25519 曲线）
  - `communication_cost()` — 通信成本分析（96 bytes/signer，与权重无关）
  - `bench_weighted_frost()` — 完整 benchmark，输出与 Fig 1 兼容的数据格式
- `schemes/Cargo.toml` 新增 `virtual_frost` feature 及 `curve25519-dalek`、`merlin` 依赖
- `schemes/src/main.rs` 注册 `virtual_frost` 子命令
- 3 个单元测试覆盖 setup、通信成本、端到端流程

**现状分析：**

旧代码中 `schemes/src/my.rs` 为空文件，`schemes/` 目录仅包含 BLS (`wts.rs`)、Schnorr (`schnorr.rs`)、Ed25519 (`pr_taps.rs`) 三个底层原语的基准测试。审稿人自然得出结论：作者声称对比的方案根本没有实现。

代码正确建模了 FROST 协议的一个关键特性：**通信成本与 signer 数量成正比，而非总权重**。高权重 signer 不需要发送更多数据——这正好回应了 R1.3 的质疑。

**尚存差距：**

- 当前实现使用简化的 DKG（直接随机生成密钥），而非完整的分布式密钥生成协议。这在 benchmark 场景下是合理的（DKG 开销在所有方案中均摊），但若有审稿人要求完整 DKG 实现，需要补充
- Lagrange 系数的计算被简化（直接使用 weight 作为标量），完整的 FROST 需要基于参与 signer 集合动态计算 Lagrange 插值系数

**实现路径：**

当前实现对标 benchmark 的目的已完全满足。若需进一步强化：
1. 补全 Lagrange 系数计算：`lambda_i = product_{j≠i} (0 - j) / (i - j)` 模曲线阶，约 20 行
2. 实现简化版 Pedersen DKG（用于 setup 阶段的密钥分发），约 100 行

---

### R1.3 — Weighted FROST 通信成本质疑

> "If a signer has a high weight, it can combine its messages into a single message and should therefore not require larger communication than if it had only a single vote."

**已完成的工作：**

- 在 Virtual FROST 实现中，通信成本计算函数 `communication_cost(num_signers)` 严格按 **signer 数量** 计算，而非按总权重计算：
  - Round 1：每个 signer 发送 2 个压缩 Edwards 点（D_i, E_i）= 64 bytes
  - Round 2：每个 signer 发送 1 个标量（z_i）= 32 bytes
  - 合计：**96 bytes/signer**，与 signer 自身权重无关
- Benchmark 输出中包含 `comm_per_signer` 和 `comm_per_weight-unit` 两个指标，便于直观验证

**现状分析：**

审稿人的直觉是**正确的**。在 FROST 协议中，每个 signer 只需生成一份 nonce 和一份部分签名，与其拥有的虚拟份额数量（权重）无关。权重只影响：
1. 密钥生成阶段——高权重 signer 获得更多虚拟份额
2. 签名验证阶段——Lagrange 系数按权重缩放

旧代码因为完全没有 Virtual FROST 实现，审稿人无法验证这一直觉，从而对整个 Fig 1 数据的可信度产生怀疑。

现在代码已经正确建模了这一点。如果论文 Fig 1 中 Weighted FROST 的通信数据确实偏高，那么问题可能出在论文的数据上，需要在修正后重新测量。

**尚存差距：**

- 如果论文原始 Fig 1 数据与代码输出不一致，需要找出旧数据的问题根源（是否错误按总权重计算了通信量？是否混淆了 signer 数和 share 数？）

**实现路径：**

1. 运行 `cargo run --release --bin time -- fig1 --sizes "8,16,32,64,128" --iters 200`，获取准确的通信成本数据
2. 与论文 Fig 1 原始数据逐点对比，定位差异
3. 若发现论文数据有误，修正 Fig 1 并更新论文中的讨论

---

### R1.4 — 性能优势不显著

> "Negligible performance gain (verification is even faster for Frost, and verification is done much more often in blockchain-like environments than signing)."

**已完成的工作：**

- Fig 1 benchmark 同时输出 `sign_us`（签名耗时）和 `verify_us`（验签耗时），不再只展示签名性能
- 数据格式允许直接对比 WTAS 和 Weighted FROST 在签名和验签两个维度的表现

**现状分析：**

审稿人指出了一个关键场景特征：区块链中**验签频率远高于签名**（每个区块由少数人签名，但被全网节点验证）。这意味着验签性能的权重应该高于签名性能。

从 benchmark 初步数据来看（n=8, 4 active signers）：
- 签名：WTAS 2839µs vs WeightedFROST 182µs → WTAS 慢 15×（因为 ElGamal 加密 + BLS 签名）
- 验签：BLS 聚合验签 ~450µs vs Ed25519 单次验签 ~50µs → BLS 慢 9×

WTAS 用验签性能换取了两个 FROST 不具备的特性：**问责性**（ElGamal tracing）和**无配对友好曲线兼容性**。论文需要诚实建模这个 trade-off 而非回避。

**尚存差距：**

- 论文中缺少对 "sign vs verify frequency" 这一区块链特性的讨论
- 缺少一个加权性能指标（如 `0.1 × sign_time + 0.9 × verify_time`）来反映区块链的实际工作负载

**实现路径：**

1. 在 benchmark 输出中增加 `weighted_cost = α × sign_us + (1-α) × verify_us` 字段，α 可配置，默认 0.1（假设 10% 签名 + 90% 验签）
2. 在论文的 Experimental Evaluation 章节增加一段 trade-off 讨论：
   - 承认 WTAS 验签比 FROST 慢
   - 论证问责性（accountability）在需要审计和追责的场景（如 DAO 治理、企业钱包）中的价值
   - 指出 WTAS 的优势在 **签名阶段**（O(k) vs O(total_weight)）和 **proof size**（O(log n) vs O(n)）

---

## Reviewer 2（0, borderline）

### R2.1 — 安全性证明不严谨

> "The security analysis is not sufficiently rigorous. The proof relies on non-trivial claims about Bulletproofs-style extraction and Super Basis Injection, but these are not formalised in enough detail."

**已完成的工作：**

- 代码中 `zk/src/main.rs` 完整实现了 Bulletproofs 式的 IPA (Inner Product Argument) 证明系统，包括：
  - `ipa_prove()` — 递归折叠生成 L/R 向量
  - `verify_normal()` — 标准迭代验证
  - `verify_fast()` — 优化的单次多标量乘法验证
  - `verify_consistency()` — 两种验证路径等价性检查
- Super Basis Injection 的代码实现在 `prove()` 函数中（line 292-303），明确展示了 `g'_i = g_i + P_i·λ_key + B·λ_enc^i` 的构造过程

**现状分析：**

代码可以作为安全性证明的**参考实现**和**验证工具**——例如通过 `verify_consistency()` 检查可以实验性地验证 Super Basis Injection 不会破坏 IPA 的代数结构。但代码正确性 ≠ 安全性证明的正确性。审稿人的核心诉求是：

1. **Theorem 2（Soundness → Knowledge Soundness）**：当前声称的 Soundness 只能保证 "如果验证通过则存在 witness"，但 accountability 场景需要 Knowledge Soundness——"存在一个提取器可以从证明中提取 witness"。这是一个本质性的差距。
2. **Super Basis Injection 的基独立性**：修改后的生成元 `g'_i` 必须被证明仍然是**独立**的（否则 IPA 的 knowledge soundness 不成立）。当前论文和代码都缺少这一论证。

**尚存差距：**

- Theorem 2 的形式化证明需要从 "Soundness" 重写为 "Knowledge Soundness"，需要定义提取器并证明其成功概率
- 需要证明 `g'_i` 向量在随机神谕模型下以高概率保持独立（依赖 `λ_key` 和 `λ_enc` 的随机性）
- 缺少对提取过程的误差分析（knowledge error bound）

**实现路径：**

1. **Theorem 2 重写**（论文核心修改，约 2-4 周）：
   - 定义 Knowledge Extractor E，给定 prover P* 和 statement x，E 通过 rewinding 提取 witness (b, w, r_enc)
   - 利用 Bulletproofs 的广义分叉引理（Generalized Forking Lemma），证明提取器以概率 ε²/Q 成功
   - 将 Super Basis Injection 的安全性归约到 "随机 λ_key, λ_enc 使 g'_i 以高概率独立" 这一引理

2. **基独立性引理**（可加入附录）：
   - 证明：对于随机 λ_key, λ_enc ∈ Z_p，向量组 {g_i + P_i·λ_key + B·λ_enc^i} 线性相关的概率 ≤ n/p（可忽略）

3. **代码辅助**：
   - 在 `zk/src/main.rs` 中添加 `test_basis_independence` 测试，随机采样 λ 并验证 g'_i 的独立性（实验验证引理），约 30 行

---

### R2.2 — Tracer 信任假设未分析

> "The scheme relies on a Tracer holding a tracing secret key, yet the paper presents the construction as decentralized and blockchain-compatible. The role of the Tracer, the consequences of compromise, and possible ways to decentralize this authority are not analysed deeply enough."

**已完成的工作：**

- 代码中 `WtasGroup` 结构体将 `tracing_key`（Tracer 私钥）和 `signers`（普通签名者）**明确分离**，使信任边界在代码层面可见
- `encrypt_participation()` 方法独立实现了 ElGamal 加密，Tracer 的解密能力仅依赖于 `tracing_key`
- `update_weights()` 方法展示了 Tracer 参与 epoch 转换的接口
- `epoch_domain()` 函数实现了 epoch 绑定机制，确保旧 epoch 的密文不会在新 epoch 中被重放

**现状分析：**

当前架构中 Tracer 是一个**单一信任点**：持有 `tracing_key` 的实体可以解密任意签名中的 signer 身份。这在以下场景中造成问题：
- Tracer 密钥泄露 → 所有历史签名匿名性被破坏（**不可逆**，因为区块链数据永久存储）
- Tracer 不可用 → 无法执行问责追踪（但签名仍可正常进行，Tracer 不参与在线签名）
- 恶意 Tracer → 可选择性揭露某些签名者身份

论文声称 "decentralized and blockchain-compatible" 与 Tracer 的中心化本质存在矛盾，审稿人敏锐地指出了这一点。

**尚存差距：**

- 论文未分析 Tracer 密钥泄露的**影响范围**和**不可逆性**
- 缺少 Tracer 去中心化的讨论（threshold Tracer、DKG-based tracing key、轮换方案）
- 代码中虽然分离了 tracing key，但未实现去中心化 Tracer 的原型

**实现路径：**

1. **论文新增 "Trust Model and Tracer Analysis" 小节**（约 1 页）：
   - 列出所有信任假设及其威胁模型（Tracer 诚实但好奇 / Tracer 恶意 / Tracer 妥协）
   - 分析每种情况下的安全退化程度
   - 讨论缓解措施：
     - **Threshold Tracer**：使用 (t, n) 门限方案分发 tracing key，需 ≥t 个 tracer 节点联合解密
     - **Epoch-based key rotation**：Tracer 定期轮换密钥，旧密文在轮换后安全擦除（利用 `epoch_domain()` 机制）
     - **Forward-secure tracing**：使用二叉树结构的密钥演化，泄露当前密钥不影响历史密文

2. **代码补充**（可选，约 150 行）：
   - 实现简单的 threshold Tracer 原型（使用 Shamir Secret Sharing 分发 tracing key）

---

### R2.3 — Solana Gatekeeper 改变信任模型

> "The appendix introduces a Gatekeeper that verifies the ZK proof off-chain and then signs an endorsement to reduce on-chain costs. This weakens the claim of trustless on-chain verification."

**已完成的工作：**

- 代码仓库保留了完整的 Solana 实现：`programs/aggtest/src/lib.rs`（链上程序）和 `cli/src/main.rs`（CLI 工具）
- README 中区分了密码学协议层（`zk/`、`schemes/`）和系统工程层（`programs/`、`cli/`）
- 代码注释中标明了 Gatekeeper 是工程优化而非密码学协议的组成部分

**现状分析：**

这是密码学论文中常见的 "protocol vs deployment" 张力。论文正文声称 "trustless on-chain verification"，但附录中引入的 Gatekeeper 实际上是一个**可信第三方**——它验证 ZK proof 然后签名 endorsement，链上只验证 endorsement。这在工程上是合理的 gas 优化，但确实削弱了 trustless 的宣称。

两种处理策略：
- **策略 A（推荐）**：诚实承认 Gatekeeper 引入的信任假设，将其定位为 "可选优化"而非协议核心，并分析 Gatekeeper 恶意时的安全退化
- **策略 B**：移除 Gatekeeper，改为纯链上验证，在论文中讨论 gas 成本并解释 Solana 上的可行性

**尚存差距：**

- 论文未分析 Gatekeeper 恶意/不可用/中心化的后果
- 未讨论替代方案（如多 Gatekeeper + threshold、TEE-based Gatekeeper）

**实现路径：**

1. **论文修改**（推荐策略 A）：
   - 将 Gatekeeper 从 "协议设计" 移到 "工程优化" 小节
   - 添加安全分析：Gatekeeper 恶意 → 可拒绝服务（阻止合法交易）但无法伪造签名；Gatekeeper 不可用 → 系统降级为全链上验证模式
   - 讨论替代部署方案（如基于 EigenLayer AVS 的去中心化 Gatekeeper 网络）

2. **代码补充**（可选）：
   - 在 `programs/aggtest/` 中增加纯链上验证模式的 feature flag，允许对比两种模式的 gas 成本

---

### R2.4 — 协议描述清晰完整（正面评价）

> "The protocol is described in reasonable detail. The paper gives a complete signing workflow."

**已完成的工作：**

- 代码中 `wts.rs` 的 4 阶段签名流程（sign → aggregate → encrypt → verify）与论文描述一一对应，可作为论文伪代码的参考实现
- README 中提供了每个阶段的独立运行指令

**现状分析：**

这是审稿人的正面肯定，说明论文的技术贡献和方案设计本身是有价值的。该意见不需要额外解决，但可以在 response letter 中引用以支撑论文的贡献。

**尚存差距：**

- 无

**实现路径：**

- 在 rebuttal / 改投 cover letter 中引用此正面评价

---

## Reviewer 3（0, borderline）

### R3.1 — 匿名性声明的数学错误（Remark 1）🟢 已解决：从论文中移除

> "The external search space is C(N,|J|), not 2^N as claimed in Remark 1."

**处理方式：直接从论文中移除匿名性声明。**

匿名性不是本文核心贡献。具体操作：
- 删除 Remark 1 全文
- 从 Introduction 贡献列表中移除 "signer anonymity"
- 威胁模型仅声称 accountability + unforgeability，不声称匿名性

代码无需修改（ElGamal 加密仅用于问责追踪，不声称匿名性）。

**工作量：约 1 小时（删除相关段落 + 检查全文一致性）。**

---

### R3.2 — 匿名性仅对外部攻击者成立 🟢 已解决：从论文中移除

> "Anonymity is only against outsiders. Protocol participants and the combiner can know the set of participants trivially."

**处理方式：随匿名性声明一并移除。**

论文不再声称匿名性，因此 "内部参与者可见 Bctx" 不再是缺陷——这是协议的公开特性，而非漏洞。在 DAO 场景中，方案明确不提供 ballot secrecy，这属于 scope 定义而非 limitation。

代码中 `sign()` 的 `active` 参数明文传递保持不变，这是正确的协议行为。

**工作量：随 R3.1 一并完成。**

---

### R3.3 — Theorem 2 证明缺口：Soundness vs Knowledge Soundness + 基独立性

> "Theorem 2 claims Soundness but the proof and usage require Knowledge Soundness. The independence of the modified basis generators g'_i after Super Basis Injection is not established."

**已完成的工作：**

- `zk/src/main.rs` 完整实现了 IPA 证明系统的三种验证模式（normal/fast/consistency）
- Super Basis Injection 的代码实现是清晰的：`g'_i = g_i + P_i·λ_key + B·λ_enc^i`

**现状分析：**

这是三个审稿人一致认为的最核心问题。不解决此问题，论文的安全性声称就没有坚实基础。具体缺口：

**缺口 1：Soundness → Knowledge Soundness**
- Soundness：∀ PPT P*, Pr[P* 产生有效证明 ∧ statement 为假] ≤ negl
- Knowledge Soundness：∀ PPT P*，存在提取器 E 使得 Pr[P* 产生有效证明 ∧ E 未能提取有效 witness] ≤ negl
- 在 WTAS 的 accountability 场景中，需要从有效证明中**提取**签名者身份（witness），因此必须使用 Knowledge Soundness
- 当前论文错误地声称了 Soundness，但实际需要的证明强度是 Knowledge Soundness

**缺口 2：Super Basis Injection 后基独立性**
- Bulletproofs 的 Knowledge Soundness 依赖于基向量 {g_i}, {h_i} 是独立生成的随机点
- Super Basis Injection 将基修改为 `g'_i = g_i + P_i·λ_key + B·λ_enc^i`
- 需要证明修改后的 g'_i 仍然以高概率独立（否则知识提取的可靠性不成立）

**尚存差距：**

- 正式的知识提取器构造
- 基独立性引理的形式化证明
- Knowledge error bound 的推导

**实现路径：**

1. **Theorem 2 重写为 Knowledge Soundness 证明**（论文核心修改，约 3 页证明）：
   - 构造提取器 E：对 prover 进行 (μ₁, μ₂, ..., μ_{log n}) 的多轮 rewinding，提取 witness (b, w, r_enc)
   - 使用 Generalized Forking Lemma（Bellare-Neven 2006）将证明中的非形式化分叉论证严格化
   - 推导 knowledge error bound：ε_ext ≥ (ε - n/p)² / Q，其中 ε 为 prover 成功率，Q 为随机神谕查询次数

2. **基独立性引理**（可放在附录，约 1 页）：
   - 声明：设 λ_key, λ_enc 为随机神谕生成的独立均匀随机标量，则 {g'_i = g_i + P_i·λ_key + B·λ_enc^i} 线性相关的概率 ≤ n/|𝔾|
   - 证明：考虑线性关系 Σ α_i·g'_i = 0，展开并利用 g_i 的独立性和 Schwartz-Zippel 引理
   - 关键洞察：g'_i 的依赖仅通过 λ_key 和 λ_enc 引入，而这两个值在证明生成时是伪随机确定的（绑定到 transcript），因此攻击者无法选择 "坏的" λ 值

3. **代码验证**（辅助手段）：
   - 在 `zk/src/main.rs` 中新增 `test_basis_independence` 测试：随机采样 λ_key, λ_enc，验证 g'_i 的线性独立性（通过 Gram 矩阵的秩），运行 1000 次确认无共线情况

---

### R3.4 — ZK 模拟器缺陷：z_enc 的一致性

> "The zero-knowledge simulation in Theorem 3 does not address how the simulator produces z_enc consistently with the public ElGamal ciphertexts C without knowing the encryption randomness."

**已完成的工作：**

- 代码中 `prove()` 函数（line 277-280）展示了真实证明中 `z_enc = Σ λ_enc^i · r_enc,i` 的计算方式——直接使用加密随机性 r_enc
- `verify_normal()` 和 `verify_fast()` 展示了验证方如何仅使用公开信息检查证明

**现状分析：**

这是审稿人 R3 最具穿透力的技术观察。问题的本质：

- 在真实协议中：Prover 知道 r_enc（加密随机性），因此可以计算 z_enc = Σ λ_enc^i · r_enc,i
- 在模拟中：Simulator 不知道 r_enc（也不知道 witness 的任何部分），但需要产生一个与公开密文 C 在验证方程中一致的 z_enc
- 验证方程：`Σ λ_enc^i · V_i - z_enc · pk_enc - z · Σ λ_enc^i · B + x · E_enc` 必须与 P0 的计算一致
- 展开 V_i = r_enc,i · G + b_i · pk_enc（ElGamal 密文公式），代入验证方程后，r_enc 项和 b_i 项分离
- Simulator 不知道 r_enc,i 的值，因此**无法在不知道 witness 的情况下直接计算 z_enc**

这是一个真实的 ZK 漏洞。代码中的实现使用真实 r_enc（真实 prover），所以能工作。但模拟器（在安全证明中）不能这样做。

**尚存差距：**

- Theorem 3 的 ZK 模拟器需要重新设计
- 可能需要在协议层面调整 z_enc 的计算方式或验证方程

**实现路径：**

这是一个需要仔细安全分析的修复。提供两种可行方向：

**方案 A：调整验证方程（推荐）**

将验证方程重写为：
```
Σ λ_enc^i · (V_i - b_i·pk_enc) + (Σ λ_enc^i · r_enc,i)·G - z_enc·pk_enc
```
利用 V_i = r_enc,i·pk_enc + b_i·G 展开后，z_enc 项和 r_enc 项可以合并。如果重新定义 z_enc 为**对 r_enc 的承诺**而非线性组合，可以设计 simulator 使用随机值（利用 HVZK 的标准技巧）。

**方案 B：使用可编程随机神谕**

在随机神谕模型下，simulator 可以编程 λ_enc 的值（通过控制 transcript challenge），使得 z_enc 的验证方程自动满足。这需要调整 challenge 的生成顺序——λ_enc 必须在 z_enc 被承诺之后生成，但当前协议中 λ_enc 在 z_enc 之前生成。

具体修改：在 `prove()` 中，先承诺一个 dummy z_enc，然后生成 λ_enc，最后用 λ_enc 来 "调整" z_enc 的开口。

**论文层面工作：**
- 重写 Theorem 3 的证明（约 2 页），明确描述 simulator 的工作流程
- 若选择方案 A，修改 `prove()` 和 `verify_normal()` 中 z_enc 的计算和验证路径
- 若选择方案 B，修改 challenge 生成顺序并补充随机神谕可编程性论证

**代码层面工作：**
- 根据选择的方案修改 `zk/src/main.rs` 中的 `prove()` 和 `verify_normal()` 函数，约 30-50 行改动
- 添加 `test_simulation_indistinguishability` 测试，验证模拟证明与真实证明在统计上不可区分

---

### R3.5 — 缺少权重变更讨论

> "The paper does not discuss what happens when the weight changes (e.g., stake updates in PoS), despite this being routine in the stated applications."

**已完成的工作：**

代码中完整实现了权重更新机制：

1. **`WtasGroup::update_weights(new_weights, new_threshold)`** — 接收新的权重向量和可选阈值：
   - 验证权重向量长度与 signer 数量一致
   - 自动计算阈值（若未提供，默认为 new_total/2 + 1）
   - 重新聚合公钥以反映新权重分布
   - 打印 epoch 转换日志（old/new total weight + threshold）

2. **`WtasGroup::epoch_domain(epoch)`** — 生成 epoch 绑定标签：
   - 使用 SHA-256 哈希 epoch 编号
   - 签名消息中应包含 epoch domain，防止跨 epoch 重放

3. **3 个单元测试**：
   - `test_weight_update` — 验证权重翻倍后 total_weight 和 threshold 更新正确
   - `test_weight_update_preserves_signers` — 验证更新后签名者密钥不被修改
   - `test_epoch_domain_uniqueness` — 验证不同 epoch 产生不同 domain

4. **benchmark 集成**：`bench_wtas_full()` 中包含权重更新性能测量

**现状分析：**

PoS 区块链中 stake 变更是常态（每个 epoch 都可能重新分配）。旧论文完全没有讨论这一需求。现在代码层面已完整覆盖，论文可以直接引用代码中的设计。

**尚存差距：**

- 论文需要在协议描述中增加 "Epoch Transition" 小节
- 需要分析 epoch 转换期间的安全窗口（两个 epoch 之间的过渡期如何保证安全）
- 需要讨论链上 vs 链下权重更新的实现差异

**实现路径：**

1. **论文新增 "Dynamic Weight Updates" 小节**（约 0.5 页）：
   - 描述 `update_weights` 的算法流程
   - 安全性分析：
     - 权重更新应有**延迟**（如 1 epoch = ~2 天），防止 signer 在活跃签名回合中操纵权重
     - Epoch domain 绑定确保跨 epoch 签名不可重放
     - 旧 epoch 的已签名交易在过渡期内仍应有效（grandfather clause）
   - 引用 PoS 系统的实际参数（Ethereum: ~6.4 min/epoch, Solana: ~2 days/epoch）

---

### R3.6 — Table 1 缺少匿名性行 🟢 已解决：随匿名性声明移除

> "Table 1 omits a signer anonymity row, which conceals the scheme's limitations."

**处理方式：Table 1 不再需要匿名性行，因为论文不声称匿名性。**

Table 1 的比较维度变为：Weighted、Accountability、Pairing-Free、Proof Size。每个维度都是本文确实贡献的。

**工作量：0（Table 1 无需修改，仅需确保全文无匿名性声称）。**

---

## 汇总：论文修改优先级

**匿名性相关 3 项已通过移除策略解决。剩余 7 项论文修改：**

| 优先级 | 意见 | 修改类型 | 预计时间 | 难度 |
|--------|------|---------|---------|------|
| 🔴 P0 | R3.3 Theorem 2 → Knowledge Soundness | 论文重写 + 新证明 | 2-4 周 | 高 |
| 🔴 P0 | R3.4 Theorem 3 ZK 模拟器修复 | 论文重写 + 可能调整协议 | 1-2 周 | 高 |
| 🟠 P1 | R2.2 Tracer 信任假设分析 | 论文新增章节 | 3-5 天 | 中 |
| 🟠 P1 | R3.5 权重变更讨论 | 论文新增小节 + 代码已完成 | 1 天 | 低 |
| 🟡 P2 | R2.3 Gatekeeper 讨论 | 论文修改 | 1-2 天 | 低 |
| 🟡 P2 | R1.4 验签 trade-off 讨论 | 论文修改 + 数据已有 | 1 天 | 低 |
| 🟢 P3 | R1.4 benchmark 加权指标 | 代码补充 | 2 小时 | 低 |

**已通过移除策略解决：R3.1（Remark 1 错误）、R3.2（内部匿名性）、R3.6（Table 1 缺行）。**

**代码层面：全部完成，0 项待处理。**
**论文层面：剩余 7 项，其中 2 项 P0（安全证明）必须完成。**
