"""CED — Coupling Error Detector.

产品耦合误差检测平台：把同一批请求灌进多个实现，比较它们的"理解"，
找出耦合误差，并判定哪些能被升级为安全影响。

模块边界（互不依赖具体实现，只依赖 contracts）：
    contracts   核心数据契约
    impls       参照实现与 HTTP/1.1 分帧解析内核
    mutate      变异引擎（6 类分歧轴）
    probe       探针：把实现包成可被差分调用的目标
    differ      差分比对（oracle）
    classify    可升级性判定（分歧 → 安全后果）
    minimize    最小化（ddmin + 语义保持）
    orchestrate 编排：拓扑、运行器、链式复现
    report      报告渲染
    store       结果落库
    cli         命令行入口
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
