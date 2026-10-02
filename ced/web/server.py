"""本地网页界面：零依赖，只用 Python 标准库。

    python -m ced web                 # 启动并自动打开浏览器
    python -m ced web --port 8777     # 指定端口
    python -m ced web --no-open       # 不自动开浏览器
"""
from __future__ import annotations

import argparse
import base64
import json
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import regression
from ..adapters import get as get_adapter
from ..analysis import all_pairs, analyze, analyze_pairs
from ..contracts import ImplSpec
from ..impls import reference
from ..orchestrate.topology import demo, load
from ..probe import Evaluator

STATIC = Path(__file__).resolve().parent
DEFAULT_PORT = 8777
#: 单条请求的字节上限 —— 本工具面向单条请求，不是整个流量包
MAX_PAYLOAD = 1 << 20


def _spec_for(impl_id: str) -> ImplSpec:
    return ImplSpec(impl_id=impl_id, name=impl_id, runner="local", policy=impl_id)


def _impls_info() -> dict:
    base = reference.REFERENCES["ref-cl-first"]
    items = []
    for name, policy in reference.REFERENCES.items():
        delta = {k: v for k, v in policy.__dict__.items()
                 if k != "name" and base.__dict__[k] != v}
        items.append({"id": name,
                      "deviation": "、".join(f"{k}={v}" for k, v in delta.items())
                                   or "基线本身"})
    return {"impls": items}


def _case_brief(spec: dict) -> dict:
    return {"id": spec["id"], "axis": spec.get("axis", ""),
            "left": spec.get("left", ""), "right": spec.get("right", ""),
            "expect_kind": spec.get("expect_kind", ""),
            "payload_len": len(base64.b64decode(spec["payload_b64"]))}


class Handler(BaseHTTPRequestHandler):
    server_version = "CED-Web/0.1"

    # ------------------------------------------------------------------ 工具
    def _send(self, body: bytes, ctype: str, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8", code)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def log_message(self, *args) -> None:      # 安静模式
        pass

    # ------------------------------------------------------------------ GET
    def do_GET(self):                                   # noqa: N802
        url = urlparse(self.path)
        query = parse_qs(url.query)

        if url.path in ("/", "/index.html"):
            return self._send((STATIC / "index.html").read_bytes(),
                              "text/html; charset=utf-8")
        if url.path == "/api/health":
            return self._json({"ok": True})
        if url.path == "/api/impls":
            return self._json(_impls_info())
        if url.path == "/api/cases":
            return self._json({"cases": [_case_brief(c)
                                         for c in regression.load_cases()]})
        if url.path == "/api/case":
            return self._case_detail((query.get("id") or [""])[0])
        return self._json({"error": "not found"}, 404)

    # ----------------------------------------------------------------- POST
    def do_POST(self):                                  # noqa: N802
        url = urlparse(self.path)
        try:
            body = self._read_body()
        except Exception as exc:
            return self._json({"error": f"请求体不是合法 JSON：{exc}"}, 400)

        if url.path == "/api/probe":
            return self._probe(body)
        if url.path == "/api/regression":
            return self._regression()
        return self._json({"error": "not found"}, 404)

    # ----------------------------------------------------------------- 业务
    def _evaluator(self, topology_path: str):
        if topology_path:
            topo = load(topology_path)
        else:
            topo = demo()
        return topo, Evaluator(topo.impls)

    def _probe(self, body: dict) -> None:
        try:
            payload = base64.b64decode(body.get("data_b64") or "", validate=True)
        except Exception as exc:
            return self._json({"error": f"data_b64 不是合法 base64：{exc}"}, 400)
        if not payload:
            return self._json({"error": "没有收到字节 —— 先选一个文件"}, 400)
        if len(payload) > MAX_PAYLOAD:
            return self._json(
                {"error": f"文件太大（{len(payload)} 字节 > {MAX_PAYLOAD}）——"
                          f"本工具面向单条请求，不是整个流量包"}, 400)

        try:
            topo, evaluator = self._evaluator((body.get("topology") or "").strip())
        except Exception as exc:
            return self._json({"error": f"拓扑文件读不了：{exc}"}, 400)

        adapter = get_adapter("http1-framing")

        if body.get("mode") == "pair":
            left, right = body.get("left"), body.get("right")
            missing = [i for i in (left, right) if i not in evaluator.specs]
            if missing:
                return self._json({"error": f"拓扑里没有这些实现：{missing}"}, 400)
            pairs = [(left, right)]
        else:
            pairs = all_pairs(evaluator.specs)

        try:
            results = analyze_pairs(payload, pairs, evaluator, adapter,
                                    minimize=True)
        except Exception as exc:
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

        return self._json({
            "payload_len": len(payload),
            "payload_repr": repr(payload),
            "topology": topo.describe(),
            "pairs_tested": len(pairs),
            "diverged": sum(1 for r in results if r["diverged"]),
            "results": results,
        })

    def _case_detail(self, case_id: str) -> None:
        cases = {c["id"]: c for c in regression.load_cases()}
        if case_id not in cases:
            return self._json({"error": f"没有这个案例：{case_id}"}, 404)
        spec = cases[case_id]
        payload = base64.b64decode(spec["payload_b64"])
        adapter = get_adapter("http1-framing")
        evaluator = Evaluator([_spec_for(spec["left"]), _spec_for(spec["right"])])
        result = analyze(payload, spec["left"], spec["right"], evaluator,
                         adapter, minimize=True)
        outcome = regression.run(cases=[spec])[0]
        return self._json({
            "case": {k: spec[k] for k in
                     ("id", "axis", "left", "right", "expect_kind",
                      "expect_fields", "reference", "note") if k in spec},
            "payload_repr": repr(payload),
            "result": result,
            "regression": {"passed": outcome.passed, "detail": outcome.detail},
        })

    def _regression(self) -> None:
        outcomes = regression.run()
        return self._json({
            "total": len(outcomes),
            "passed": sum(1 for o in outcomes if o.passed),
            "items": [{"name": o.name, "passed": o.passed, "detail": o.detail}
                      for o in outcomes],
        })


# ---------------------------------------------------------------------- 启动

def serve(port: int = DEFAULT_PORT, host: str = "127.0.0.1") -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"CED 网页界面已启动：{url}", flush=True)
    print("在此终端按 Ctrl+C 停止。", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ced web", description="CED 本地网页界面")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-open", action="store_true", help="不要自动打开浏览器")
    args = ap.parse_args(argv)

    if not args.no_open:
        threading.Thread(
            target=lambda: (time.sleep(0.6),
                            webbrowser.open(f"http://{args.host}:{args.port}/")),
            daemon=True).start()
    serve(args.port, args.host)
    return 0
