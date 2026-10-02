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


def _cmd_cases(_: argparse.Namespace) -> int:
    from . import regression
    cases = regression.load_cases()
    if not cases:
        print("[!] cases/known/ 下没有案例文件")
        return 1
    print(f"{'案例':<28}{'分歧轴':<18}{'对照':<46}期望")
    print("-" * 108)
    for c in cases:
        pair = f"{c['left']} ↔ {c['right']}"
        print(f"{c['id']:<28}{c['axis']:<18}{pair:<46}{c.get('expect_kind', '')}")
    print(f"\n共 {len(cases)} 个案例。看详情：python -m ced case <id>")
    return 0


def _dump(payload: bytes) -> None:
    parts = payload.split(b"\r\n")
    for i, part in enumerate(parts):
        suffix = "\\r\\n" if i < len(parts) - 1 else ""
        print(f"    {part.decode('latin-1')}{suffix}")


def _cmd_case(args: argparse.Namespace) -> int:
    import base64

    from . import regression
    from .adapters import get as get_adapter
    from .classify.upgradability import judge
    from .contracts import ImplSpec
    from .differ.comparator import compare
    from .impls import reference
    from .probe import Evaluator

    cases = {c["id"]: c for c in regression.load_cases()}
    if args.id not in cases:
        raise SystemExit(f"[!] 没有这个案例：{args.id}\n"
                         f"    可选：{', '.join(sorted(cases))}")
    spec = cases[args.id]
    payload = base64.b64decode(spec["payload_b64"])

    if args.raw:                       # 直接吐原始字节，可管道给 nc / curl
        sys.stdout.flush()
        sys.stdout.buffer.write(payload)
        return 0

    adapter = get_adapter("http1-framing")
    left_id, right_id = spec["left"], spec["right"]
    evaluator = Evaluator([
        ImplSpec(impl_id=left_id, name=left_id, runner="local", policy=left_id),
        ImplSpec(impl_id=right_id, name=right_id, runner="local", policy=right_id),
    ])
    left = evaluator(left_id, payload)
    right = evaluator(right_id, payload)

    print(f"案例      {spec['id']}")
    print(f"分歧轴    {spec['axis']}")
    print(f"对照      {left_id}  ↔  {right_id}")
    print(f"期望      {spec.get('expect_kind')} · 字段 {spec.get('expect_fields')}")
    print(f"出处      {spec.get('reference', '—')}")
    print(f"说明      {spec.get('note', '—')}")
    print(f"\n原始字节（{len(payload)} B）：")
    _dump(payload)

    div = compare(spec["id"], spec["axis"], payload, left, right, adapter.compare_keys)
    print(f"\n两侧观测：")
    print(f"    {'字段':<18}{left_id:<26}{right_id}")
    for key in adapter.compare_keys:
        mark = "  ←" if (div and key in div.keys) else ""
        print(f"    {key:<18}{str(left.get(key)):<26}{right.get(key)}{mark}")

    if div is None:
        print("\n结果      两侧理解一致 —— 未构成耦合误差（期望值可能写错了）")
        return 1

    kind = adapter.classify([d.key for d in div.diffs])
    verdict = judge(div, kind, adapter, evaluator)
    print(f"\n分歧字段  {', '.join(div.keys)}")
    print(f"分类      {kind}")
    print(f"判定      {verdict.level}")
    print(f"理由      {verdict.reason}")
    if verdict.ablation:
        print(f"可控性    {verdict.ablation}")
    print(f"CWE       {verdict.cwe or '—'}"
          + (f"　场景 {verdict.scenario}" if verdict.scenario else ""))
    print(f"安全后果  {verdict.effect}")
    print(f"修复建议  {verdict.fix}")

    outcome = regression.run(cases=[spec])[0]
    print(f"\n回归      {'PASS' if outcome.passed else 'FAIL'}  {outcome.detail}")
    return 0 if outcome.passed else 1


def _observations(left, right, compare_keys, diff_keys) -> None:
    print(f"     {'字段':<18}{left.impl_id:<26}{right.impl_id}")
    for key in compare_keys:
        mark = "  ←" if key in diff_keys else ""
        print(f"     {key:<18}{str(left.get(key)):<26}{right.get(key)}{mark}")


def _cmd_probe(args: argparse.Namespace) -> int:
    """探测一份原始字节：对全部（或指定）实现做差分，直接出判定。"""
    import itertools

    from .classify.upgradability import judge
    from .differ.comparator import compare

    payload = (sys.stdin.buffer.read() if args.file == "-"
               else Path(args.file).read_bytes())
    if not payload:
        raise SystemExit("[!] 输入为空")

    topo = load(args.topology) if args.topology else demo()
    adapter = get_adapter(args.domain)
    evaluator = Evaluator(topo.impls)

    print(f"输入      {args.file}  （{len(payload)} 字节）")
    print(f"拓扑      {topo.describe()}")
    print("\n原始字节：")
    _dump(payload)

    if args.pair:
        missing = [i for i in args.pair if i not in evaluator.specs]
        if missing:
            raise SystemExit(f"[!] 拓扑里没有这些实现：{missing}\n"
                             f"    可选：{', '.join(evaluator.specs)}")
        pairs = [tuple(args.pair)]
    else:
        pairs = list(itertools.combinations(list(evaluator.specs), 2))

    hits = []
    for left_id, right_id in pairs:
        left = evaluator(left_id, payload)
        right = evaluator(right_id, payload)
        div = compare("probe", "probe", payload, left, right, adapter.compare_keys)
        if div is None:
            if args.show:
                print(f"\n[—] {left_id} ↔ {right_id}：两侧理解一致")
                _observations(left, right, adapter.compare_keys, set())
            continue
        kind = adapter.classify([d.key for d in div.diffs])
        verdict = judge(div, kind, adapter, evaluator)
        hits.append((left_id, right_id, left, right, div, kind, verdict))

    print(f"\n比较      {len(pairs)} 组 → 发现分歧 {len(hits)} 组")
    if not hits:
        print("\n所有组合在结构字段上理解一致。")
        print("注意：这不等于安全，只说明在这份输入上两侧没有分歧。")
        return 0

    for left_id, right_id, obs_l, obs_r, div, kind, verdict in hits:
        print(f"\n{'-' * 72}")
        print(f"{left_id}  ↔  {right_id}      判定 {verdict.level}  （{kind}）")
        if args.pair:
            print()
            _observations(obs_l, obs_r, adapter.compare_keys, set(div.keys))
        print(f"  分歧字段  {', '.join(div.keys)}")
        print(f"  理由      {verdict.reason}")
        if verdict.ablation:
            print(f"  可控性    {verdict.ablation}")
        if verdict.cwe:
            print(f"  CWE       {verdict.cwe}　场景 {verdict.scenario}")
        print(f"  后果      {verdict.effect}")
        print(f"  修复      {verdict.fix}")

    if not args.pair:
        print(f"\n{'=' * 72}")
        print("看某一对的完整观测：python -m ced probe <file> --pair "
              f"{hits[0][0]} {hits[0][1]}")
    return 0


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

    cs = sub.add_parser("cases", help="列出全部已知案例")
    cs.set_defaults(func=_cmd_cases)

    c = sub.add_parser("case", help="摊开一个已知案例（原始字节 + 两侧观测 + 判定）")
    c.add_argument("id", help="案例 id，见 python -m ced cases")
    c.add_argument("--raw", action="store_true",
                   help="只输出原始字节，可管道给 nc/curl 打靶")
    c.set_defaults(func=_cmd_case)

    p = sub.add_parser("probe", help="探测一份原始字节文件（任意请求），对全部或指定实现做差分")
    p.add_argument("file", help="原始字节文件；用 - 从 stdin 读")
    p.add_argument("--pair", nargs=2, metavar=("LEFT", "RIGHT"),
                   help="只比较指定的一对实现，并打印两侧完整观测")
    p.add_argument("--topology", default=None, help="拓扑文件（YAML/JSON）；缺省用内置 demo")
    p.add_argument("--domain", default="http1-framing", choices=sorted(ADAPTERS))
    p.add_argument("--show", action="store_true", help="即使无分歧也打印两侧观测")
    p.set_defaults(func=_cmd_probe)

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
