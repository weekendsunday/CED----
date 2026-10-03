# 测试样本

给「检测」页/CLI 直接用的输入文件。**下面每个文件的结论都是在本机实跑出来的**，
不是"期望值" —— 换台机器、改了参照实现，数字会变（`ced/tests/test_samples.py` 会盯住它）。

## 怎么用

三种都行：

```bash
python main.py                       # 打开网页 → 检测 → 把文件拖进去（或点「选择文件」）
```

```bash
# 命令行（等价内核）
python -c "from ced.detect import run; import pathlib; r=run(pathlib.Path('samples/01-benign-request.bin').read_bytes().decode('latin-1')); print(r['summary'])"
```

- **原始请求一律用 .bin**：`\r\n` 是字节，用记事本打开另存会把换行改掉，字节就不保真了。
  网页上的「选择文件」是**按字节读入**的，所以 .bin 拖进去不会走样。
- **别往粘贴框里粘这些请求**：浏览器的表单会把 `\r\n` 规范化成 `\n`（页面会当场警告你）。
  粘文本类输入（nuclei / curl / URL 清单）没这个问题。

## 原始请求（10 个）

| 文件 | 是什么 | 实测结论 |
|---|---|---|
| `01-benign-request.bin` | 一条完全正常的 POST | **0 分歧**（对照组：所有实现读法一致，防假阳性） |
| `02-cl-te-smuggling.bin` | `Content-Length` 与 `Transfer-Encoding` 并存 + 夹带第二条请求 | 分歧 15 / **安全级 15**｜`http1-framing` `framing_boundary` **CWE-444** |
| `03-cl-leading-zero.bin` | `Content-Length: 03` 前导零 | 分歧 8 / 安全级 8｜`http1-framing` CWE-444 |
| `04-conflicting-cl.bin` | 两个冲突的 `Content-Length`（3 与 4） | 分歧 8 / 安全级 8｜`http1-framing` CWE-444 |
| `05-chunked-bare-lf.bin` | 分块体用裸 LF 作行尾 | 分歧 8 / 安全级 8｜`http1-framing` CWE-444 |
| `06-host-trailing-dot.bin` | `Host: example.com.` 尾随点 | 分歧 8 / 安全级 8｜`host-norm` `host_interpretation` **CWE-436**（虚拟主机绕过 / 缓存投毒） |
| `07-path-traversal.bin` | `/static/../admin` 路径穿越 | 分歧 11 / 安全级 11｜`url-norm` `path_traversal` **CWE-22** |
| `08-query-pollution.bin` | `a=1&a=2` + 二次编码 | 分歧 43 / 安全级 31｜最强 `enc-norm` `enc_interpretation` **CWE-180** |
| `09-enc-uXXXX.bin` | `%u002e%u002e`（IIS 遗留转义） | 分歧 9 / 安全级 9｜`enc-norm` `enc_interpretation` CWE-180 |
| `10-absolute-form.bin` | 代理形式的绝对 URI 请求行 | 分歧 29 / 安全级 28｜`http1-framing` CWE-444 |

这 10 个覆盖了 **5 个领域**（分帧 / 路径 / Host / 查询串 / 编码），每个都带 1 个**对照组**在上面。

## 外部工具的发现（5 种格式，`external/`）

| 文件 | 格式 | 实测结论（三态） |
|---|---|---|
| `nuclei-results.json` | nuclei JSON | 已证实 1 / 未证实 1 / 证不了 0 |
| `burp-sitemap.xml` | Burp XML | 已证实 1 / 未证实 1 / 证不了 0 |
| `devtools.har` | HAR（浏览器导出） | 已证实 1 / 未证实 1 / 证不了 0 |
| `curl-commands.sh` | curl 命令行 | 已证实 1 / 未证实 2 / 证不了 0 |
| `urls.txt` | URL 清单 | 已证实 2 / 未证实 1 / 证不了 0 |

这些走的是**另一条链**：把外部扫描器的命中当"待验证的假设"重跑同一条 oracle 链，
输出**已证实 / 未证实 / 证不了** —— 其中「未证实」是保守口径：只说明试过的这些领域里
参照实现看不出分歧，**不等于**这条发现是假的。

## pcap 呢？

不支持。请在 wireshark 里把流导出成 **HAR**，或者用控制台的「自动捕获」把请求直接收进来。
