# 产品耦合误差报告

- 领域：`http1-framing`
- 拓扑：domain=http1-framing impls=9 chain=ref-cl-first → ref-te-first
- 用例数：60　实现对：8
- 耦合误差：24　其中安全级：22

## 分级统计

| 级别 | 数量 |
|---|---|
| security | 22 |
| unknown | 2 |

| 分歧类型 | 数量 |
|---|---|
| framing_boundary | 24 |

## 误差明细（按级别排序）

### [security] `8b2611d2` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-lenient-cl**（轴：`cl_value`）
- 判定理由：消息边界解释分歧（字段 ['framing_source', 'cl', 'body_len', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：移除请求头 `Content-Length: 03` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-lenient-cl |
|---|---|---|
| `framing_source` | `'none'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `56` | `59` |
| `leftover_len` | `3` | `0` |

- 最小复现样本（59 → 42 字节）：

  ```
  b'POST / HTTP/1.1\r\nContent-Length: 03\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-lenient-cl** 串联：前置转发 39 字节，后端只消费 0 字节 → **39 字节被夹带**，将成为下一条请求的开头

### [security] `d1df52a0` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-lenient-cl**（轴：`cl_value`）
- 判定理由：消息边界解释分歧（字段 ['framing_source', 'cl', 'body_len', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：移除请求头 `Content-Length: +3` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-lenient-cl |
|---|---|---|
| `framing_source` | `'none'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `56` | `59` |
| `leftover_len` | `3` | `0` |

- 最小复现样本（59 → 42 字节）：

  ```
  b'POST / HTTP/1.1\r\nContent-Length: +3\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-lenient-cl** 串联：前置转发 39 字节，后端只消费 0 字节 → **39 字节被夹带**，将成为下一条请求的开头

### [security] `44f044fe` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-lenient-cl**（轴：`cl_value`）
- 判定理由：消息边界解释分歧（字段 ['framing_source', 'cl', 'body_len', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：移除请求头 `Content-Length: 0000003` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-lenient-cl |
|---|---|---|
| `framing_source` | `'none'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `61` | `64` |
| `leftover_len` | `3` | `0` |

- 最小复现样本（64 → 47 字节）：

  ```
  b'POST / HTTP/1.1\r\nContent-Length: 0000003\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-lenient-cl** 串联：前置转发 44 字节，后端只消费 0 字节 → **44 字节被夹带**，将成为下一条请求的开头

### [security] `3d0a4b5b` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-lenient-cl**（轴：`cl_value`）
- 判定理由：消息边界解释分歧（字段 ['framing_source', 'cl', 'body_len', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：移除请求头 `CONTENT-LENGTH: +3` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-lenient-cl |
|---|---|---|
| `framing_source` | `'none'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `56` | `59` |
| `leftover_len` | `3` | `0` |

- 最小复现样本（59 → 42 字节）：

  ```
  b'POST / HTTP/1.1\r\nCONTENT-LENGTH: +3\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-lenient-cl** 串联：前置转发 39 字节，后端只消费 0 字节 → **39 字节被夹带**，将成为下一条请求的开头

### [security] `4d4c1c3b` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-lenient-cl**（轴：`cl_value`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'cl', 'body_len', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：移除请求头 `Content-Length: 3`；移除请求头 `Content-Length: 4` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-lenient-cl |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `0` | `77` |
| `leftover_len` | `0` | `1` |

- 最小复现样本（78 → 61 字节）：

  ```
  b'POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd'
  ```

- 链式复现：若 **ref-cl-first → ref-lenient-cl** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `de0a72c9` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-lenient-cl**（轴：`cl_value`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'cl', 'body_len', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：移除请求头 `CONTENT-LENGTH: 3`；移除请求头 `Content-Length: 4` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-lenient-cl |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `0` | `77` |
| `leftover_len` | `0` | `1` |

- 最小复现样本（78 → 61 字节）：

  ```
  b'POST / HTTP/1.1\r\nCONTENT-LENGTH: 3\r\nContent-Length: 4\r\n\r\nabcd'
  ```

- 链式复现：若 **ref-cl-first → ref-lenient-cl** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `1cfdd820` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-lenient-cl**（轴：`cl_value`）
- 判定理由：消息边界解释分歧（字段 ['cl', 'body_len', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：移除请求头 `Content-Length: +3` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-lenient-cl |
|---|---|---|
| `cl` | `4` | `3` |
| `body_len` | `4` | `3` |
| `consumed` | `79` | `78` |
| `leftover_len` | `0` | `1` |

- 最小复现样本（79 → 43 字节）：

  ```
  b'POST / HTTP/1.1\r\nContent-Length: +3\r\n\r\nabcd'
  ```

- 链式复现：若 **ref-cl-first → ref-lenient-cl** 串联：前置转发 39 字节，后端只消费 0 字节 → **39 字节被夹带**，将成为下一条请求的开头

### [security] `41d4a9a7` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-headers**（轴：`header_syntax`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：移除请求头 `Host: localhost`；移除请求头 ` injected: fold` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-headers |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'none'` |
| `consumed` | `0` | `73` |
| `leftover_len` | `0` | `3` |

- 最小复现样本（76 → 56 字节）：

  ```
  b'POST / HTTP/1.1\r\nHost: localhost\r\n injected: fold\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-headers** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `ff9e2e44` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-headers**（轴：`header_syntax`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：移除请求头 ` injected: fold` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-headers |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'none'` |
| `consumed` | `0` | `73` |
| `leftover_len` | `0` | `3` |

- 最小复现样本（76 → 59 字节）：

  ```
  b'POST / HTTP/1.1\r\nContent-Length: 03\r\n injected: fold\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-headers** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `2eedc234` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-headers**（轴：`header_syntax`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：移除请求头 ` injected: fold` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-headers |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'none'` |
| `consumed` | `0` | `73` |
| `leftover_len` | `0` | `3` |

- 最小复现样本（76 → 59 字节）：

  ```
  b'POST / HTTP/1.1\r\nContent-Length:  3\r\n injected: fold\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-headers** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `823440d4` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-headers**（轴：`header_syntax`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：移除请求头 ` injected: fold` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-headers |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'none'` |
| `consumed` | `0` | `74` |
| `leftover_len` | `0` | `3` |

- 最小复现样本（77 → 60 字节）：

  ```
  b'POST / HTTP/1.1\r\nContent-Length: 0x3\r\n injected: fold\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-headers** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `62ba123b` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-request-line**（轴：`request_line`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'cl', 'body_len', 'consumed']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：把请求行规范化成 `POST / HTTP/1.1` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-request-line |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `0` | `58` |

- 最小复现样本（58 → 41 字节）：

  ```
  b'post / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-request-line** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `70162be0` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-request-line**（轴：`request_line`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'cl', 'body_len', 'consumed']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：把请求行规范化成 `POST / HTTP/1.1` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-request-line |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `0` | `58` |

- 最小复现样本（58 → 41 字节）：

  ```
  b'post / HTTP/1.1\r\nCONTENT-LENGTH: 3\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-request-line** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `b8f75cf9` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-request-line**（轴：`request_line`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：把请求行规范化成 `POST / HTTP/1.1` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-request-line |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'none'` |
| `consumed` | `0` | `56` |
| `leftover_len` | `0` | `3` |

- 最小复现样本（59 → 42 字节）：

  ```
  b'post / HTTP/1.1\r\nContent-Length: +3\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-request-line** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `276c3a0e` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-request-line**（轴：`request_line`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：把请求行规范化成 `POST / HTTP/1.1` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-request-line |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'none'` |
| `consumed` | `0` | `57` |
| `leftover_len` | `0` | `3` |

- 最小复现样本（60 → 43 字节）：

  ```
  b'post / HTTP/1.1\r\nContent-Length: abc\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-request-line** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `fc4c74fb` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-request-line**（轴：`request_line`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：把请求行规范化成 `POST / HTTP/1.1` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-request-line |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'none'` |
| `consumed` | `0` | `78` |
| `leftover_len` | `0` | `3` |

- 最小复现样本（81 → 43 字节）：

  ```
  b'post / HTTP/1.1\r\nContent-Length: 0x3\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-request-line** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `63b954dd` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-request-line**（轴：`request_line`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：把请求行规范化成 `POST / HTTP/1.1` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-request-line |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'none'` |
| `consumed` | `0` | `74` |
| `leftover_len` | `0` | `3` |

- 最小复现样本（77 → 43 字节）：

  ```
  b'post / HTTP/1.1\r\nContent-Length: 0x3\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-request-line** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `c8f519aa` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-request-line**（轴：`request_line`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'cl', 'body_len', 'consumed', 'leftover_len']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：把请求行规范化成 `POST / HTTP/1.1` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-request-line |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `0` | `94` |
| `leftover_len` | `0` | `43` |

- 最小复现样本（137 → 101 字节）：

  ```
  b'POST  http://localhost/ HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcGET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-request-line** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `c6b4341c` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-request-line**（轴：`request_line`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'cl', 'body_len', 'consumed']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：把请求行规范化成 `POST / HTTP/1.1` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-request-line |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `0` | `77` |

- 最小复现样本（77 → 41 字节）：

  ```
  b'post / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-request-line** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `2204c027` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-request-line**（轴：`request_line`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'cl', 'body_len', 'consumed']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：把请求行规范化成 `POST / HTTP/1.1` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-request-line |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `0` | `96` |

- 最小复现样本（96 → 41 字节）：

  ```
  b'post / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-request-line** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `f2b69e5e` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-request-line**（轴：`request_line`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'cl', 'body_len', 'consumed']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：把请求行规范化成 `POST / HTTP/1.1` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-request-line |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `0` | `94` |

- 最小复现样本（94 → 58 字节）：

  ```
  b'POST  http://localhost/ HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-request-line** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [security] `7e6ac820` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-request-line**（轴：`request_line`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'te', 'body_len', 'consumed']），且由攻击者可直接发送的部分（请求行/请求头）承载 → 具备请求走私的结构性前提
- 可控性证据：把请求行规范化成 `POST / HTTP/1.1` —— 分歧消失，说明它由攻击者可直接发送的部分承载
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-request-line |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'te'` |
| `te` | `[]` | `['Chunked']` |
| `body_len` | `0` | `5` |
| `consumed` | `0` | `79` |

- 最小复现样本（79 → 62 字节）：

  ```
  b'post / HTTP/1.1\r\nTransfer-Encoding: Chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
  ```

- 链式复现：若 **ref-cl-first → ref-loose-request-line** 串联：前置未转发任何字节（按自身策略拒绝）→ 不产生夹带；但『一侧拒绝、一侧接受』本身构成绕过/可用性面

### [unknown] `c5cb884a` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-lenient-cl**（轴：`cl_value`）
- 判定理由：消息边界解释分歧（字段 ['framing_source', 'cl', 'body_len', 'consumed', 'leftover_len']），但消融实验无法定位到单条可控头 → 需人工复核
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-lenient-cl |
|---|---|---|
| `framing_source` | `'none'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `76` | `79` |
| `leftover_len` | `3` | `0` |

- 原始样本：

  ```
  b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 03\r\nContent-Length: 03\r\n\r\nabc'
  ```

### [unknown] `4efb4378` — framing_boundary

- 对照：**ref-cl-first** ↔ **ref-loose-request-line**（轴：`request_line`）
- 判定理由：消息边界解释分歧（字段 ['accepted', 'status', 'framing_source', 'cl', 'body_len', 'consumed']），但消融实验无法定位到单条可控头 → 需人工复核
- 安全后果：两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）
- CWE：CWE-444　场景：**desync**
- 修复建议：对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式

| 观测字段 | ref-cl-first | ref-loose-request-line |
|---|---|---|
| `accepted` | `False` | `True` |
| `status` | `400` | `200` |
| `framing_source` | `'reject'` | `'cl'` |
| `cl` | `None` | `3` |
| `body_len` | `0` | `3` |
| `consumed` | `0` | `76` |

- 原始样本：

  ```
  b'post  http://localhost/ HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3 \r\n\r\nabc'
  ```

---

> `security` 级 = 消息边界分歧 ∧ 分歧点由攻击者可控请求头承载。
> 未通过可控性消融的分歧一律标为 `unknown`，不作结论。