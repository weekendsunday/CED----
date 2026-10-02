# 产品耦合误差报告

- 领域：`http1-framing`
- 拓扑：domain=http1-framing impls=4 chain=customer-gateway → ref-cl-first
- 用例数：4　实现对：5
- 前置拒绝、不可观测而跳过的用例：**9**（不合成观测；真实前置对畸形请求返回 4xx 属正常行为）
- 耦合误差：3　其中安全级：0

## 分级统计

| 级别 | 数量 |
|---|---|
| unknown | 3 |

| 分歧类型 | 数量 |
|---|---|
| framing_boundary | 3 |

## 同类归并

> 判据：**同一对实现 + 同一分歧类型 = 同一类事实**，只留一条代表。
> 3 条发现归并后是 **3 类**（冗余 **1.0×**）。完整清单仍在 JSON 与结果库里。

| 级别 | 链路 | 类型 | 条数 | 代表 |
|---|---|---|---|---|
| unknown | customer-gateway ↔ ref-cl-first | `framing_boundary` | 1 | `a35bb609` |
| unknown | customer-gateway ↔ ref-lenient-cl | `framing_boundary` | 1 | `a35bb609` |
| unknown | customer-gateway ↔ ref-te-first | `framing_boundary` | 1 | `a35bb609` |

## 误差明细（每类一条代表）

### [unknown] `a35bb609` — framing_boundary

- 对照：**customer-gateway** ↔ **ref-cl-first**（轴：`cross`）
- 判定理由：结构字段分歧（['consumed']），但消融实验无法定位到单条可控承载者 → 需人工复核
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | customer-gateway | ref-cl-first |
|---|---|---|
| `consumed` | `112` | `58` |

- 原始样本：

  ```
  b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc'
  ```

### [unknown] `a35bb609` — framing_boundary

- 对照：**customer-gateway** ↔ **ref-lenient-cl**（轴：`cross`）
- 判定理由：结构字段分歧（['consumed']），但消融实验无法定位到单条可控承载者 → 需人工复核
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | customer-gateway | ref-lenient-cl |
|---|---|---|
| `consumed` | `112` | `58` |

- 原始样本：

  ```
  b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc'
  ```

### [unknown] `a35bb609` — framing_boundary

- 对照：**customer-gateway** ↔ **ref-te-first**（轴：`cross`）
- 判定理由：结构字段分歧（['consumed']），但消融实验无法定位到单条可控承载者 → 需人工复核
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | customer-gateway | ref-te-first |
|---|---|---|
| `consumed` | `112` | `58` |

- 原始样本：

  ```
  b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc'
  ```

---

> `security` 级 = 消息边界分歧 ∧ 分歧点由攻击者可控请求头承载。
> 未通过可控性消融的分歧一律标为 `unknown`，不作结论。