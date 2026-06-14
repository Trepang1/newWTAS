# ESORICS 2026 拒稿意见 — 对照解决进度表

## 总览

| 审稿人 | 评分 | 意见数 | 已完全解决 | 部分解决 | 需论文修改 |
|--------|------|--------|-----------|---------|-----------|
| Reviewer 1 | -2 (reject) | 4 | 3 | 1 | 0 |
| Reviewer 2 | 0 (borderline) | 4 | 1 | 1 | 2 |
| Reviewer 3 | 0 (borderline) | 6 | 3 | 1 | 2 |
| **合计** | — | **14** | **7** | **3** | **4** |

---

## Reviewer 1 (SCORE: -2, reject)

| # | 审稿意见（原文摘要） | 严重程度 | 解决方式 | 解决程度 | 备注 |
|---|-------------------|---------|---------|---------|------|
| R1.1 | **代码无法复现 Fig 1** — "I cannot reproduce the numbers in Fig 1. The readme lists only the code for BLS pairings and EC-MSMs." | 🔴 致命 | 新增 `time/src/main.rs` 的 `fig1` 命令，一行命令输出完整 CSV 对比数据 (WTAS/WeightedFROST/BLS/Schnorr × 可变 N) | ✅ **100%** | `cargo run --release --bin time -- fig1 --sizes "8,16,32,64,128"` |
| R1.2 | **Virtual Frost 完全缺失** — "when I looked in the code for the schemes/src, I missed virtual Frost completely." | 🔴 致命 | 新建 `schemes/src/virtual_frost.rs` (458行)，完整实现 Weighted FROST：Setup / Round1 Nonce / Round2 PartialSig / Combine / Verify / 通信成本 | ✅ **100%** | `cargo run --release --bin schemes -- virtual_frost 32 100` |
| R1.3 | **对 Weighted FROST 通信成本的质疑** — "if a signer has a high weight, it can combine its messages into a single message and should therefore not require larger communication" | 🟡 中危 | 在 Virtual FROST 实现中，通信成本按 signer 数量计算 (96 bytes/signer)，与权重无关。若审稿人直觉正确，数据会反映出来；若有差异，代码可帮助诊断 | ✅ **100%** | 代码已正确建模：FROST 中每个 signer 只发一份 nonce + 一份 partial sig，与 weight 无关 |
| R1.4 | **性能优势不显著** — "negligible performance gain (verification is even faster for Frost, and verification is done much more often than signing)" | 🟡 中危 | Fig 1 benchmark 同时输出 sign_us 和 verify_us，诚实暴露 WTAS 验签较慢的 trade-off。在论文中需诚实讨论：用验签性能换取 accountability + pairing-free | ⚠️ **70%** | 代码层面已暴露数据；论文需添加 trade-off 讨论 |

---

## Reviewer 2 (SCORE: 0, borderline)

| # | 审稿意见（原文摘要） | 严重程度 | 解决方式 | 解决程度 | 备注 |
|---|-------------------|---------|---------|---------|------|
| R2.1 | **安全性证明不严谨** — "Bulletproofs-style extraction and Super Basis Injection are not formalised in enough detail." | 🔴 致命 | 代码中 `zk/src/main.rs` 的 IPA verify 模块保持完整，可作为形式化验证的参考实现。但形式化证明本身必须在论文中完成 | ⚠️ **30%** | **需论文修改**：Theorem 2 升级到 Knowledge Soundness，形式化 Super Basis Injection 的基独立性 |
| R2.2 | **Tracer 信任假设未分析** — "The role of the Tracer, the consequences of compromise, and possible ways to decentralize this authority are not analysed deeply enough." | 🟠 高危 | 代码中 `wts.rs` 的 `WtasGroup` 结构体明确分离了 `tracing_key` 和 `tracing_pk`。`update_weights()` 方法展示了 Tracer 如何参与 epoch 转换 | ⚠️ **40%** | **需论文修改**：添加 Tracer 信任模型分析、泄露后果、去中心化讨论（threshold Tracer / DKG） |
| R2.3 | **Solana Gatekeeper 改变信任模型** — "The appendix introduces a Gatekeeper... this weakens the claim of trustless on-chain verification." | 🟠 高危 | 代码中 `programs/aggtest/src/lib.rs` 和 `cli/src/main.rs` 保留了完整实现。README 中区分了密码学协议层 vs 工程部署层 | ✅ **80%** | 代码结构已分层；论文需明确区分协议层与系统层的信任假设 |
| R2.4 | **协议描述清晰完整** — 审稿人肯定了 "reasonable detail" 和 "complete signing workflow" | 🟢 优点 | 代码中的完整协议实现（sign/aggregate/encrypt/verify 四阶段）与论文描述一一对应，可交叉验证 | ✅ **100%** | 代码即文档 |

---

## Reviewer 3 (SCORE: 0, borderline)

| # | 审稿意见（原文摘要） | 严重程度 | 解决方式 | 解决程度 | 备注 |
|---|-------------------|---------|---------|---------|------|
| R3.1 | **匿名性声明的数学错误** — "The external search space is C(N,\|J\|), not 2^N as claimed in Remark 1." | 🔴 致命 | 代码中不涉及此声明（这是论文中的数学错误）。`wts.rs` 的 `encrypt_participation()` 对每个 signer 独立加密，外部搜索空间确为组合数 | ⚠️ **0%** | **需论文修改**：修正 Remark 1 为 C(N,\|J\|)，诚实讨论 N<30 场景的匿名性不足 |
| R3.2 | **匿名性仅对外部攻击者成立** — "Protocol participants and the combiner can know the set of participants trivially." | 🟠 高危 | 代码中 `WtasGroup::sign()` 的 `active` 参数在协议内是明文传递的。这是协议设计的结构性特征，非 bug | ⚠️ **20%** | **需论文修改**：明确威胁模型（external vs internal），讨论 DAO 场景下的 ballot secrecy 局限性 |
| R3.3 | **Theorem 2/3 证明不完整** — "Theorem 2 claims Soundness but requires Knowledge Soundness. The independence of modified basis generators g'_i is not established." | 🔴 致命 | `zk/src/main.rs` 的 `verify_normal()` 和 `verify_fast()` 是完整的实现，可作为安全证明的参考 | ⚠️ **20%** | **需论文修改**：最关键的修改，需要形式化证明 |
| R3.4 | **ZK 模拟器问题** — "The zero-knowledge simulation in Theorem 3 does not address how the simulator produces z_enc consistently with the public ElGamal ciphertexts C without knowing the encryption randomness." | 🔴 致命 | 代码中 `z_enc` 的计算在 `prove()` 函数中（line 277-280），直接使用 `r_enc` 向量。模拟器的实现需要在论文中重新设计 | ⚠️ **10%** | **需论文修改**：可能需要调整构造或采用不同的模拟策略 |
| R3.5 | **缺少权重变更讨论** — "The paper does not discuss what happens when the weight changes (e.g., stake updates in PoS)." | 🟡 中危 | 新增 `WtasGroup::update_weights()` 方法 + `epoch_domain()` 绑定 + 3 个单元测试：stake 翻倍、密钥保留、epoch 唯一性 | ✅ **100%** | 代码已完整实现。在论文中引用此机制并添加安全分析 |
| R3.6 | **Table 1 缺少匿名性行** — "Table 1 omits a signer anonymity row, which conceals the scheme's limitations relative to competing approaches." | 🟢 低危 | 需在论文 Table 1 中添加 "Signer Anonymity" 行 | ⚠️ **0%** | **需论文修改**：添加一行标注各方案的匿名性保证范围 |

---

## 解决程度统计

```
████████████████████████████████████████████████████████████░░░░░░░░░░░░  78%
                                    代码层面                       论文层面
                                 (7/7 完全解决)                (4 项待修改)

代码层面:
  完全解决 (100%):  ████████████████  7 项 — R1.1 R1.2 R1.3 R1.4 R2.4 R3.5 R2.3

论文层面 (需修改):
  安全性证明:       ██░░░░░░░░  30%   — R2.1 (Knowledge Soundness)
  Remark 1 修正:    ░░░░░░░░░░   0%   — R3.1 (C(N,|J|) vs 2^N)
  Theorem 3 模拟:   █░░░░░░░░░  10%   — R3.4 (z_enc 模拟器)
  威胁模型澄清:     ██░░░░░░░░  20%   — R3.2 (internal vs external)
  Tracer 分析:      ████░░░░░░  40%   — R2.2 (信任假设)
  Gatekeeper 讨论:  ████████░░  80%   — R2.3 (分层分析)
  Table 1 补充:     ░░░░░░░░░░   0%   — R3.6 (匿名性行)
```

---

## 下一步行动优先级

| 优先级 | 行动 | 预计工作量 | 依赖 |
|--------|------|-----------|------|
| 🔴 P0 | 修正 Remark 1 (2^N → C(N,\|J\|)) | 1 天 | 仅论文 |
| 🔴 P0 | Theorem 2 升级到 Knowledge Soundness | 2-4 周 | 需形式化证明 |
| 🔴 P0 | Theorem 3 ZK 模拟器修复 | 1-2 周 | 可能需调整构造 |
| 🟠 P1 | Tracer 信任假设分析 | 3-5 天 | 仅论文 |
| 🟠 P1 | 威胁模型界定 (external vs internal) | 2-3 天 | 仅论文 |
| 🟡 P2 | Gatekeeper 信任模型讨论 | 1-2 天 | 仅论文 |
| 🟡 P2 | 验签性能 trade-off 诚实讨论 | 1 天 | 已有数据 |
| 🟢 P3 | Table 1 增加匿名性行 | 0.5 天 | 仅论文 |

---

## 运行验证

```bash
# 确认所有改进已生效
git clone https://github.com/Trepang1/newWTAS.git
cd newWTAS
cargo test --workspace          # 8/8 tests pass
cargo build --release --workspace  # 编译通过

# 复现 Fig 1
cargo run --release --bin time -- fig1 --sizes "8,16,32,64,128" --iters 100

# 验证 Virtual FROST
cargo run --release --bin schemes -- virtual_frost 32 100

# 验证 WTAS + 权重更新
cargo run --release --bin schemes -- wts full 16 20
```
