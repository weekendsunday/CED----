# CED 项目包

> **自包含可移植包**：源码、文档、跑出来的结果、原始素材全在里面。
> 拷到任何一台装了 Python 3.11+ 的机器上即可运行 —— **无需联网、无需 pip install、无需 Docker**。
>
> 一句话：客户把产品交给我们，我们找出它们在**串联处的耦合误差**。
> 单独看 nginx 没问题，单独看 gunicorn 没问题，`nginx + gunicorn` 就有 desync。

---

## 换机器怎么用（三步）

1. 把整个 `CED-项目包` 文件夹拷过去（U 盘 / 网盘 / 压缩包都行）
2. 确认有 Python 3.11+：`python --version`
3. 跑自检 —— Windows 直接双击 **`selfcheck.bat`**
   其他系统依次执行下面四条命令：

```bash
cd CED-项目包
python ced/tests/test_pipeline.py      # 引擎与判定（16 项）
python ced/tests/test_socket_probe.py  # 探针协议一致性（2 项）
python ced/tests/test_chain_e2e.py     # 前置→探针 端到端（5 项）
python -m ced regression               # 已知案例反验证
```

看到三次 `OK` 加 `8/8 通过`，说明环境正常。

---

## 目录导览

| 路径 | 是什么 | 提交赛题时 |
|---|---|---|
| `ced/` | **源代码**（纯 Python，零第三方依赖，48 个文件） | ✅ 必交 |
| `docs/部署运行说明.md` | 怎么部署、怎么跑、怎么扩展、怎么排错 | ✅ 必交 |
| `docs/技术方案.md` | 目标对象、服务形态、指标、排期 | 可选 |
| `docs/漏洞挖掘步骤.md` | 漏洞挖掘方法论（前期调研） | 可选 |
| `docs/团队分工.md` | 4 人任务分工 | ❌ 内部材料 |
| `docs/diffmine审查报告.md` | 对队友那份实现的审查与修复记录 | ❌ 内部材料 |
| `results/` | 跑出来的报告、JSON、结果库（**效果证据**） | 可选 |
| `refs/` | 原始素材：队友的实现包 + 赛题说明 | ❌ 原始素材，不必交 |
| `selfcheck.bat` | Windows 一键自检 | ✅ 便于专家验证 |

---

## 手动运行

```bash
cd CED-项目包

python -m ced impls        # 列出参照实现与定向对照
python -m ced regression   # 已知案例反验证 → 应 8/8 通过
python -m ced scan --mode axis --limit 60 --out results/new.md --db results/new.db
```

预期：

```
[结果] 用例 60 | 实现对 8 | 耦合误差 24 | 安全级 11
== 已知案例反验证：8/8 通过 ==
```

> ⚠️ `python -m ced` 必须在**包根目录**下执行（`ced` 是包名，换目录会报 `ModuleNotFoundError: ced`）。

---

## 压缩时的坑

用 Windows 资源管理器右键「压缩」，中文文件名会按 GBK 存进 ZIP，换台机器解压可能变成 `╬─╝■` 乱码
（我们在队友的包上踩过这个坑）。

**建议用 7-Zip**，或用 Python 自带工具：

```bash
python -m zipfile -c CED.zip CED-项目包
```

---

## 提交赛题时的命名

赛题要求：`自主命题 + 作品名称 + 团队名称 + 源代码`

例：`自主命题+CED产品耦合误差检测+XX队+源代码`

把 `CED-项目包` 按上面的规则重命名，并按导览表剔除标 ❌ 的内部材料即可。

---

## 合规声明

本作品仅在本机容器矩阵与**已获授权**的链路上运行，不针对任何未授权的真实目标实施测试；
不要求客户提供源码，全程黑盒观测。
