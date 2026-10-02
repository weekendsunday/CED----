"""命令行入口。

    python -m ced scan  --mode axis --limit 60 --out report.md --db ced.db
    python -m ced scan  --mode cross --topology topo.yaml
    python -m ced serve --policy ref-te-first --port 8800
    python -m ced impls
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
from pathlib import Path

from .adapters import ADAPTERS, get as get_adapter
from .impls import reference
from .orchestrate.topology import demo, load
from .pipeline import scan
from .probe import Evaluator, ProbeUnreachable
from .report.renderer import render_json, render_markdown
from . import store


def _print_event(event: dict) -> None:
    """把任务事件流打到终端 —— CLI 与网页控制台消费的是同一套事件。"""
    kind = event.get("type")
    if kind == "stage":
        print(f"[{event.get('stage', '')}] {event.get('detail', '')}")
    elif kind == "proposals":
        print(f"[提案] {event.get('detail', '')}")
        for item in event.get("items", []):
            mark = "命中" if item.get("admitted") else "未命中"
            print(f"    [{mark}] {item.get('axis', ''):<34}{item.get('note', '')[:70]}")
    elif kind == "progress":
        print(f"[进度] {event.get('done')}/{event.get('total')}　"
              f"分歧 {event.get('divergences')}　安全级 {event.get('security')}")


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

    extra: list[tuple[str, bytes]] = []
    if args.llm:
        from .scan import runner as scan_runner
        conn = store.connect(scan_runner.db_path())
        try:
            extra = scan_runner.prepare_proposals(_print_event, adapter,
                                                  evaluator, conn)
        finally:
            conn.close()

    try:
        result = scan(adapter, evaluator, mode=topo_mode, limit=args.limit,
                      seed=args.seed, do_minimize=not args.no_minimize,
                      extra_cases=extra)
    except ProbeUnreachable as exc:
        # 链路探测失败绝不产出"发现" —— 那会是一整片假阳性
        raise SystemExit(f"[!] 链路不可用，已中止（不产出任何结论）：{exc}") from exc

    report = render_markdown(result, domain=topo.domain, topo_desc=topo.describe(),
                             poc_dir=args.poc_dir)
    Path(args.out).write_text(report, encoding="utf-8")

    print("-" * 62)
    print(f"[结果] 用例 {result.total_cases} | 实现对 {result.jobs} | "
          f"耦合误差 {len(result.divergences)} | 安全级 {len(result.security)}")
    if result.rejected_cases:
        print(f"[说明] 前置按自身策略拒绝了 {result.rejected_cases} 条用例"
              f"（后端视角不存在），已跳过 —— 不合成观测，也不中止扫描")
    for f in result.security:
        print(f"  [!!] {f.case_id}  {f.divergence.left.impl_id} ↔ "
              f"{f.divergence.right.impl_id}  {f.verdict.kind}"
              f"{f'  最小化 {f.original_len}→{f.minimized_len}B' if f.minimized else ''}")
    print(f"[产物] {args.out}")

    # 攻击场景升级：只对 security 级出 PoC（判定器没升级的，这里不替它升级）
    from .scenario import build_pocs, write_pocs

    pocs = build_pocs(result)
    if pocs:
        paths = write_pocs(result, args.poc_dir)
        print(f"[产物] {args.poc_dir}  （{len(paths)} 个端到端 PoC 脚本）")
        for path in paths[:3]:
            print(f"        {path}")
        if len(paths) > 3:
            print(f"        … 等 {len(paths)} 个")
    else:
        print("[产物] 无 security 级发现，因此没有 PoC（不夸大）")

    if args.json:
        Path(args.json).write_text(render_json(result), encoding="utf-8")
        print(f"[产物] {args.json}")
    if args.db:
        conn = store.open_fresh(args.db)
        store.save_scan(conn, result, adapter.name)
        if pocs:
            store.save_pocs(conn, pocs, script_dir=args.poc_dir)
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


def _cmd_poc(args: argparse.Namespace) -> int:
    """摊开一条 security 级发现的端到端 PoC：场景 + 字节归属 + 步骤 + 可执行脚本。

    刻意**重跑一次同 seed 的扫描**来重建这条发现 —— 扫描是确定性的，
    所以这比"从库里捞上一次的残留"更可复现，也避免读到别的实验留下的数据。
    """
    from .scenario import build_pocs

    try:
        adapter = get_adapter(args.domain)
    except KeyError as exc:
        raise SystemExit(f"[!] {exc}") from exc

    topo = load(args.topology) if args.topology else demo()
    evaluator = Evaluator(topo.impls)
    try:
        result = scan(adapter, evaluator, mode=args.mode, limit=args.limit,
                      seed=args.seed, do_minimize=not args.no_minimize)
    except ProbeUnreachable as exc:
        raise SystemExit(f"[!] 链路不可用，已中止（不产出任何结论）：{exc}") from exc

    pocs = {p.case_id: p for p in build_pocs(result)}
    if not pocs:
        raise SystemExit("[!] 本次扫描没有 security 级发现，因此没有 PoC 可出。\n"
                         "    判定器没升级的分歧不会生成 PoC —— 这是刻意的。")
    if args.case_id not in pocs:
        raise SystemExit(f"[!] 没有这个用例的 PoC：{args.case_id}\n"
                         f"    可选：{', '.join(sorted(pocs))}")

    poc = pocs[args.case_id]

    if args.stdout:
        # 这个模式就是给管道用的：只吐脚本，不掺人类可读的前言
        sys.stdout.write(poc.script)
        return 0

    print(f"用例      {poc.case_id}　　场景 {poc.scenario}　{poc.title}")
    print(f"链路      {poc.left} → {poc.right}　　判定 {poc.level}　CWE {poc.cwe or '—'}")
    if poc.forwarded is None:
        print("字节归属  无法量化（两侧含非本地实现）—— 需在真实拓扑上复现")
    else:
        print(f"字节归属  前置转发 {poc.forwarded} / 后端消费 {poc.back_consumed} / "
              f"被夹带 {poc.smuggled_len} 字节")
    print(f"样本      {poc.original_len} → {poc.sample_len} 字节")

    print(f"\n影响\n  {poc.impact}")
    print(f"\n可控性证据\n  {poc.evidence}")
    print(f"\n链式复现\n  {poc.chain_desc}")

    print("\n复现步骤")
    for index, step in enumerate(poc.steps, 1):
        print(f"  {index}. {step}")

    print(f"\n最小复现样本（{poc.sample_len} 字节）")
    _dump(poc.request)

    directory = Path(args.out)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / poc.file_name
    path.write_text(poc.script, encoding="utf-8")
    print(f"\nPoC 脚本  {path}")
    print(f"          python {path}                                     # 离线算字节账")
    print(f"          python {path} --send HOST:PORT --i-am-authorized   # 授权后真发")
    return 0


def _cmd_agent(args: argparse.Namespace) -> int:
    """闭环 agent：让模型看着上一轮的执行结果决定下一步往哪里搜。

    模型只选工具、不判定；每条发现仍由确定性内核给出。
    没配置模型时降级为单轮确定性扫描，结果与不带 agent 完全一致。
    """
    from .agent import ToolBox
    from .agent import run as agent_run
    from .assist.client import LlmClient, config_from_env
    from .scan import runner as scan_runner
    from .scenario import build_pocs, write_pocs

    adapter = get_adapter(args.domain)
    topo = load(args.topology) if args.topology else demo()
    evaluator = Evaluator(topo.impls)

    client = LlmClient(config_from_env())
    conn = store.connect(args.db or scan_runner.db_path())
    toolbox = ToolBox(adapter, evaluator, conn=conn, client=client,
                      mode=args.mode, limit=args.limit, seed=args.seed,
                      max_calls=args.max_calls)

    print("=" * 66)
    print(f"闭环 agent　目标：{args.goal}")
    print(f"模型：{'已配置 ' + config_from_env().model if client.available else '未配置（降级为单轮确定性扫描）'}"
          f"　预算：{args.rounds} 轮 / {args.max_calls} 次工具调用")
    print("=" * 66)

    def emit(event: dict) -> None:
        if event.get("type") == "agent":
            mark = "ok" if event.get("ok") else "FAILED"
            note = (event.get("note") or "").replace("\n", " ")[:100]
            print(f"[第 {event.get('round')} 轮] {event.get('tool'):<16}{mark:<8}{note}",
                  flush=True)

    try:
        outcome = agent_run(goal=args.goal, toolbox=toolbox, client=client,
                            max_rounds=args.rounds, on_event=emit)
    finally:
        conn.close()

    print("-" * 66)
    print("运行轨迹：")
    for step in outcome.steps:
        mark = "ok" if step.ok else "FAILED"
        print(f"  {step.round}. {step.tool:<16}{mark:<8}{(step.why or '')[:70]}")
    if outcome.error:
        print(f"  [!] {outcome.error}")

    merged = outcome.merged()
    print("-" * 66)
    print(f"[结果] 累计用例 {merged.total_cases} | 耦合误差 {len(merged.divergences)} | "
          f"安全级 {len(merged.security)}")
    for finding in merged.security:
        print(f"  [!!] {finding.case_id}  {finding.divergence.left.impl_id} ↔ "
              f"{finding.divergence.right.impl_id}  {finding.verdict.kind}")
    print(f"[结论] {outcome.summary}")

    report = render_markdown(merged, domain=topo.domain, topo_desc=topo.describe(),
                             poc_dir=args.poc_dir)
    Path(args.out).write_text(report, encoding="utf-8")
    print(f"[产物] {args.out}")

    pocs = build_pocs(merged)
    if pocs:
        paths = write_pocs(merged, args.poc_dir)
        print(f"[产物] {args.poc_dir}  （{len(paths)} 个端到端 PoC 脚本）")

    if args.json:
        Path(args.json).write_text(render_json(merged), encoding="utf-8")
        print(f"[产物] {args.json}")
    return 0


def _cmd_assist(args: argparse.Namespace) -> int:
    """模型提案的独立入口：配置状态 / 生成一批并跑准入实验 / 看命中率台账。

    与扫描完全解耦 —— 没有模型时这条命令只是告诉你"没配"，不影响任何扫描路径。
    """
    from .assist import compile as acompile
    from .assist import ledger as aledger
    from .assist import propose as apropose
    from .assist.client import LlmClient, config_from_env
    from .mutate import axes
    from .scan import runner as scan_runner

    cfg = config_from_env()
    client = LlmClient(cfg)
    conn = store.connect(scan_runner.db_path())
    try:
        want_action = bool(args.propose or args.ledger)
        if args.status or not want_action:
            print(f"模型状态    {'已配置' if client.available else '未配置'}")
            print(f"base_url    {cfg.base_url or '—'}")
            print(f"model       {cfg.model or '—'}")
            print(f"台账库      {scan_runner.db_path()}")
            if not client.available:
                print("\n说明        扫描不依赖模型 —— 未配置时全链路自动降级为纯确定性模式。")
                print("           配置 CED_LLM_BASE_URL / CED_LLM_MODEL / CED_LLM_API_KEY 即可启用。")
            if not want_action:
                print("\n用法        python -m ced assist --propose 8   要 8 条提案并逐条跑准入实验")
                print("            python -m ced assist --ledger     看提案命中率台账")
                return 0

        if args.propose:
            if not client.available:
                raise SystemExit("[!] 未配置模型，无法提案。用 python -m ced assist 查看状态。")
            adapter = get_adapter("http1-framing")
            evaluator = Evaluator(demo().impls)
            proposals, rejected, _raw = apropose.propose(
                client, adapter_name=adapter.name, n=args.propose,
                existing_axes=axes.AXES,
                history=store.proposal_history_brief(conn))
            for item in rejected:
                aledger.record_rejected(conn, item)
            admissions = acompile.admit(proposals, adapter, evaluator)
            aledger.record_many(conn, admissions)

            hits = sum(1 for a in admissions if a.admitted)
            print(f"模型返回    {len(proposals) + len(rejected)} 条　"
                  f"通过语法门槛 {len(proposals)} 条　被丢弃 {len(rejected)} 条")
            print(f"准入实验    {hits}/{len(admissions)} 条真的逼出了结构分歧\n")
            for a in admissions:
                print(f"  [{'命中' if a.admitted else '未命中'}] "
                      f"{a.proposal.axis:<32}{a.proposal.proposal_id}")
                print(f"           {a.detail}")
            for r in rejected:
                print(f"  [丢弃] {r.axis or '(无名)':<32}{r.reason}：{r.detail[:80]}")

        if args.ledger:
            stats = store.proposal_stats(conn)
            print(f"提案 {stats['proposed']}　可编译 {stats['compiled']}　"
                  f"命中 {stats['admitted']}　命中率 {stats['hit_rate']:.1%}")
            for origin, s in sorted(stats["by_origin"].items()):
                label = {"llm": "模型", "handwritten": "手写"}.get(origin, origin)
                print(f"  {label:<6}提案 {s['proposed']}　命中 {s['admitted']}　"
                      f"命中率 {s['hit_rate']:.1%}")
            print("\n最近提案：")
            for row in store.recent_proposals(conn, 20):
                mark = "命中" if row["admitted"] else (
                    "未命中" if row["compiled"] else "丢弃")
                print(f"  [{mark:<3}] {row['axis']:<34}{row['origin']:<12}"
                      f"{row['note'][:56]}")
            print("\n口径：命中 = 提案通过了差分 oracle 的准入实验（真的逼出结构分歧），"
                  "不是模型自述。")
        return 0
    finally:
        conn.close()


def _cmd_web(args: argparse.Namespace) -> int:
    from .web.server import main as web_main
    argv = ["--port", str(args.port), "--host", args.host]
    if args.no_open:
        argv.append("--no-open")
    return web_main(argv)


def _cmd_serve(args: argparse.Namespace) -> int:
    from .probe.front import MODES
    from .probe.front import serve as front_serve
    from .probe.server import serve

    if args.front:
        if args.front_mode not in MODES and args.front_mode not in reference.REFERENCES:
            raise SystemExit(
                f"[!] 未知前置模式：{args.front_mode}\n"
                f"    可选：{', '.join(MODES)}，或参照实现策略名"
                f"（{', '.join(reference.REFERENCES)}）")
        # 两个进程一条真实链路：客户端 → 替身前置 → 探针（扮演后端）
        threading.Thread(
            target=front_serve,
            args=(args.front_mode, args.front_port, args.data_port, args.host),
            daemon=True).start()

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
    s.add_argument("--llm", action="store_true",
                   help="让模型提案（需配置 CED_LLM_*）；提案必须先通过差分 oracle "
                        "的准入实验才进语料，通不过的直接丢弃")
    s.add_argument("--out", default="report.md")
    s.add_argument("--poc-dir", default="results/pocs",
                   help="端到端 PoC 脚本输出目录（只对 security 级发现生成）")
    s.add_argument("--json", default=None)
    s.add_argument("--db", default=None)
    s.set_defaults(func=_cmd_scan)

    w = sub.add_parser("web", help="启动本地网页界面（点鼠标操作，不用记命令）")
    w.add_argument("--port", type=int, default=8777)
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--no-open", action="store_true", help="不自动打开浏览器")
    w.set_defaults(func=_cmd_web)

    v = sub.add_parser("serve", help="起探针服务（供 socket / chain 方式接入真实产品）")
    v.add_argument("--policy", default="ref-cl-first")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--data-port", type=int, default=8800)
    v.add_argument("--api-port", type=int, default=8801)
    v.add_argument("--front", action="store_true",
                   help="同时起一个替身前置（无 Docker 时演示「前置 → 后端」链路）")
    v.add_argument("--front-port", type=int, default=18080,
                   help="替身前置的对外入口（别用 8080：Windows 常保留该端口）")
    v.add_argument("--front-mode", default="pass",
                   help="pass | rewrite_cl | drop | 参照实现策略名（如 ref-te-first）")
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

    pc = sub.add_parser("agent", help="闭环 agent：模型看着执行结果决定下一步往哪搜（判定仍在内核）")
    pc.add_argument("--goal", default="在内置语料之外，找出新的可升级耦合误差",
                    help="给 agent 的总目标（自然语言）")
    pc.add_argument("--rounds", type=int, default=4, help="最多几轮（每轮一次工具调用）")
    pc.add_argument("--max-calls", type=int, default=12, help="工具调用总预算（硬上限）")
    pc.add_argument("--mode", choices=["axis", "cross"], default="axis")
    pc.add_argument("--limit", type=int, default=60)
    pc.add_argument("--seed", type=int, default=42)
    pc.add_argument("--topology", default=None, help="拓扑文件；缺省用内置 demo")
    pc.add_argument("--domain", default="http1-framing", choices=sorted(ADAPTERS))
    pc.add_argument("--out", default="results/agent-report.md")
    pc.add_argument("--poc-dir", default="results/pocs")
    pc.add_argument("--json", default=None)
    pc.add_argument("--db", default=None, help="台账库（默认 ced.db，用于命中率回写）")
    pc.set_defaults(func=_cmd_agent)

    pc = sub.add_parser("poc", help="摊开一条 security 级发现的端到端 PoC（场景 + 字节归属 + 复现脚本）")
    pc.add_argument("case_id", help="用例 id，见 python -m ced scan 的输出")
    pc.add_argument("--out", default="results/pocs", help="PoC 脚本输出目录")
    pc.add_argument("--stdout", action="store_true", help="把脚本打到标准输出，不落盘")
    pc.add_argument("--topology", default=None, help="拓扑文件；缺省用内置 demo")
    pc.add_argument("--domain", default="http1-framing", choices=sorted(ADAPTERS))
    pc.add_argument("--mode", choices=["axis", "cross"], default="axis")
    pc.add_argument("--limit", type=int, default=None,
                    help="用例数上限（需与生成该发现时一致）")
    pc.add_argument("--seed", type=int, default=42)
    pc.add_argument("--no-minimize", action="store_true")
    pc.set_defaults(func=_cmd_poc)

    a = sub.add_parser("assist", help="模型提案：配置状态 / 生成一批并跑准入实验 / 命中率台账")
    a.add_argument("--status", action="store_true", help="显示模型配置状态")
    a.add_argument("--propose", type=int, metavar="N",
                   help="向模型要 N 条提案，逐条跑差分 oracle 准入实验")
    a.add_argument("--ledger", action="store_true", help="查看提案命中率台账")
    a.set_defaults(func=_cmd_assist)
    return ap


def _silence_stdout() -> None:
    """下游关闭了管道时，把 stdout 接到空设备，别再写。

    POSIX 上这类情况是 ``BrokenPipeError``；Windows 上是 ``OSError: Errno 22``。
    两种都不是程序出错（`python -m ced ... | head` 就是正常用法），
    安静退出即可 —— 但要先静音 stdout，否则解释器退出时会再报一次。
    """
    try:
        sys.stdout.flush()
    except OSError:
        pass
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        _silence_stdout()
        return 0
    except OSError as exc:
        if getattr(exc, "errno", None) in (22, 32):      # EINVAL / EPIPE
            _silence_stdout()
            return 0
        raise


if __name__ == "__main__":
    raise SystemExit(main())
