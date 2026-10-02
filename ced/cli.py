"""命令行入口。

    python -m ced scan  --mode axis --limit 60 --out report.md --db ced.db
    python -m ced scan  --mode cross --topology topo.yaml
    python -m ced serve --policy ref-te-first --port 8800
    python -m ced impls
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .adapters import ADAPTERS, get as get_adapter
from .impls import reference
from .orchestrate.topology import demo, load
from .pipeline import scan
from .probe import Evaluator, ProbeUnreachable
from .report.renderer import render_json, render_markdown
from . import store


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        adapter = get_adapter(args.domain)
    except KeyError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    topo = load(args.topology) if args.topology else demo()
    if args.mode:
        topo_mode = args.mode
    else:
        topo_mode = "axis"
    evaluator = Evaluator(topo.impls)
    try:
        result = scan(adapter, evaluator, mode=topo_mode, limit=args.limit,
                      seed=args.seed, do_minimize=not args.no_minimize)
    except ProbeUnreachable as exc:
        # 链路探测失败绝不产出"发现" —— 那会是一整片假阳性
        raise SystemExit(f"[!] 链路不可用，已中止（不产出任何结论）：{exc}") from exc

    report = render_markdown(result, domain=topo.domain, topo_desc=topo.describe())
    Path(args.out).write_text(report, encoding="utf-8")

    print("-" * 62)
    print(f"[结果] 用例 {result.total_cases} | 实现对 {result.jobs} | "
          f"耦合误差 {len(result.divergences)} | 安全级 {len(result.security)}")
    for f in result.security:
        print(f"  [!!] {f.case_id}  {f.divergence.left.impl_id} ↔ "
              f"{f.divergence.right.impl_id}  {f.verdict.kind}"
              f"{f'  最小化 {f.original_len}→{f.minimized_len}B' if f.minimized else ''}")
    print(f"[产物] {args.out}")

    if args.json:
        Path(args.json).write_text(render_json(result), encoding="utf-8")
        print(f"[产物] {args.json}")
    if args.db:
        conn = store.open_fresh(args.db)
        store.save_scan(conn, result, adapter.name)
        print(f"[产物] {args.db}  {store.stats(conn)}")
        conn.close()
    return 0


def _cmd_regression(_: argparse.Namespace) -> int:
    from . import regression
    outcomes = regression.run()
    if not outcomes:
        print("[!] cases/known/ 下没有案例文件")
        return 1
    width = max(len(o.name) for o in outcomes)
    for o in outcomes:
        print(f"  [{'PASS' if o.passed else 'FAIL'}] {o.name:<{width}}  {o.detail}")
    passed = sum(1 for o in outcomes if o.passed)
    print(f"== 已知案例反验证：{passed}/{len(outcomes)} 通过 ==")
    return 0 if passed == len(outcomes) else 1


def _cmd_serve(args: argparse.Namespace) -> int:
    from .probe.server import serve
    serve(args.host, args.data_port, args.api_port, reference.policy_of(args.policy))
    return 0


def _cmd_impls(_: argparse.Namespace) -> int:
    from .impls.reference import BASE, REFERENCES
    print("参照实现（runner=local）：")
    for name, pol in REFERENCES.items():
        delta = {k: v for k, v in pol.__dict__.items()
                 if k != "name" and BASE.get(k) != v}
        print(f"  {name:<24} 偏离基线: {delta or '(基线本身)'}")
    print("\n定向对照：")
    for axis, (l, r) in reference.AXIS_PAIRS.items():
        print(f"  {axis:<18} {l} ↔ {r}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ced", description="CED — 产品耦合误差检测")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="跑一次差分扫描并出报告")
    s.add_argument("--domain", default="http1-framing", choices=sorted(ADAPTERS),
                   help="领域适配器（新增领域见 ced/adapters/__init__.py 的注册表）")
    s.add_argument("--topology", default=None, help="拓扑文件（YAML/JSON）；缺省用内置 demo")
    s.add_argument("--mode", choices=["axis", "cross"], default=None,
                   help="axis=按分歧轴定向对照；cross=全部两两组合")
    s.add_argument("--limit", type=int, default=None, help="用例数上限")
    s.add_argument("--seed", type=int, default=42, help="随机种子（可复现）")
    s.add_argument("--no-minimize", action="store_true", help="跳过最小化")
    s.add_argument("--out", default="report.md")
    s.add_argument("--json", default=None)
    s.add_argument("--db", default=None)
    s.set_defaults(func=_cmd_scan)

    v = sub.add_parser("serve", help="起探针服务（供 socket / chain 方式接入真实产品）")
    v.add_argument("--policy", default="ref-cl-first")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--data-port", type=int, default=8800)
    v.add_argument("--api-port", type=int, default=8801)
    v.set_defaults(func=_cmd_serve)

    r = sub.add_parser("regression", help="已知案例反验证（平台有效性自证，改判定后必跑）")
    r.set_defaults(func=_cmd_regression)

    i = sub.add_parser("impls", help="列出参照实现与定向对照")
    i.set_defaults(func=_cmd_impls)
    return ap


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
